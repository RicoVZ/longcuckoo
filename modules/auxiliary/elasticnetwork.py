import json
import dpkt
import socket
import logging
import threading
import os
import time
import io

from elasticsearch import Elasticsearch, helpers
from httpreplay.cut import http_handler, forward_handler
from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import NetworkData


log = logging.getLogger(__name__)


def read_tcp(packet, sent, receive):
    max_bytes = 1500
    try:
        packet.add_attr("body_sent", sent[:max_bytes])
        packet.add_attr("body_recv", receive[:max_bytes])
        if packet.body_sent is not None:
            packet.add_attr("len_sent", len(sent))
        if packet.body_recv is not None:
            packet.add_attr("len_recv", len(receive))
    except TypeError as e:
        # log exception
        pass

    return packet

def read_http(packet, sent, receive):
    attrs_sent = [
        "uri",
        "method",
        "body",
        "headers",
    ]

    attrs_recv = [
        "body",
        "status",
        "headers"
    ]

    for attr in attrs_sent:
        packet.add_attr("%s_sent" % attr, getattr(sent, attr, None))

    for attr in attrs_recv:
        packet.add_attr("%s_recv" % attr, getattr(receive, attr, None))

    if packet.body_sent is not None:
        packet.add_attr("len_sent", len(sent.body))
    if packet.body_recv is not None:
        packet.add_attr("len_recv", len(receive.body))

    return packet

def read_icmp(packet, ip):
    ip_data = ip.data
    packet.protocol = "icmp"
    packet.add_attr("type_number", ip_data.type)
    if ip_data.type == 0 or ip_data.type == 8:
        packet.data = ip_data.data.data

    return packet

def read_udp(packet, ip):
    ip_data = ip.data
    packet.protocol = "udp"
    packet.data = ip_data.data
    packet.length = ip.len

    return packet

def read_dns(packet, ip):
    qtypes = {
        dpkt.dns.DNS_A: "A",
        dpkt.dns.DNS_AAAA: "AAAA",
        dpkt.dns.DNS_CNAME: "CNAME",
        dpkt.dns.DNS_MX: "MX",
        dpkt.dns.DNS_PTR: "PTR",
        dpkt.dns.DNS_NS: "NS",
        dpkt.dns.DNS_SOA: "SOA",
        dpkt.dns.DNS_TXT: "TXT",
        dpkt.dns.DNS_HINFO: "HINFO",
        dpkt.dns.DNS_SRV: "SRV",
        dpkt.dns.DNS_ANY: "ANY"
    }

    dns = dpkt.dns.DNS(ip.data.data)
    packet.protocol = "dns"

    if len(dns.qd) < 1:
        return packet

    name = dns.qd[0].name
    qtype = dns.qd[0].type

    packet.add_attr("query_type", qtypes.get(qtype, "Unknown"))
    packet.add_attr("dns_query", name)

    answers = []
    for qa in dns.an:
        ans = {
            "type": qtypes.get(qa.type, "Unknown")
        }
        data = ""

        if qa.type == dpkt.dns.DNS_A:
            try:
                data = socket.inet_ntoa(qa.rdata)
            except socket.error:
                continue
        elif qa.type == dpkt.dns.DNS_AAAA:
            try:
                data = socket.inet_pton(socket.AF_INET6, qa.rdata)
            except (socket.error, ValueError, AttributeError, TypeError) as e:
                # AttributeError is thrown on Windows, pton not available
                log.error("Error %s ipv6 value is: %s", e, repr(qa.rdata))
                continue
        elif qa.type == dpkt.dns.DNS_CNAME:
            data = qa.cname
        elif qa.type == dpkt.dns.DNS_TXT:
            data = " ".join(qa.text)
        elif qa.type == dpkt.dns.DNS_MX:
            data = qa.mxname
        elif qa.type == dpkt.dns.DNS_PTR:
            data = qa.ptrname
        elif qa.type == dpkt.dns.DNS_NS:
            data = qa.nsname
        elif qa.type == dpkt.dns.DNS_HINFO:
            data = " ".join(qa.answer.text)
        elif qa.type == dpkt.dns.DNS_SOA:
            data = ",".join([
                qa.mname, qa.rname, str(qa.serial), str(qa.refresh),
                str(qa.retry), str(qa.expire), str(qa.minimum)
            ])

        ans["data"] = data
        answers.append(ans)

    if len(answers) > 0:
        packet.add_attr("dns_answer", answers)

    return packet


class PacketFilter(object):
    readers_dpkt = {
        dpkt.icmp.ICMP: read_icmp,
        dpkt.udp.UDP: read_udp,
        53: read_dns
    }

    readers_httpreplay = {
        80: http_handler,
        8080: http_handler,
        "generic": forward_handler
    }

    def __init__(self, pcap_path, file_offset=0, pcap_glob_header=None):
        self.pcap_path = pcap_path
        self.file_offset = file_offset
        self.file_pos = None
        self.pcap_header = pcap_glob_header
        self.packets = []
        self.file_pos = 0

    def _filter_packets_dpkt(self, fp):

        try:
            pcap_f = dpkt.pcap.Reader(fp)
        except (ValueError, dpkt.dpkt.NeedData):
            # No packets or invalid packets
            return

        for ts, buf in pcap_f:
            ethernet = dpkt.ethernet.Ethernet(buf)

            # Only look at IP traffic
            if ethernet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = ethernet.data
            protocol = type(ip.data)
            if not isinstance(ip.data, dpkt.dpkt.Packet):
                continue

            packet = NetworkData()
            packet.src = socket.inet_ntoa(ip.src)
            packet.dst = socket.inet_ntoa(ip.dst)
            packet.timestamp = ts

            if hasattr(ip.data, "sport") and hasattr(ip.data, "dport"):
                packet.sport = ip.data.sport
                packet.dport = ip.data.dport

            handler = None
            if packet.dport in self.readers_dpkt:
                handler = self.readers_dpkt[packet.dport]
            elif packet.sport in self.readers_dpkt:
                handler = self.readers_dpkt[packet.sport]
            elif protocol in self.readers_dpkt:
                handler = self.readers_dpkt[protocol]

            if handler is not None:
                try:
                    p = handler(packet, ip)
                    log.debug("DPKT_PACKET: %s", repr(p))
                    self.packets.append(p)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                    continue

    def _filter_packets_httpreplay(self, fp):

        handlers = {
            "http": read_http,
            "tcp": read_tcp
        }

        try:
            pcap_f = PcapReader(fp)
        except (ValueError, dpkt.dpkt.NeedData):
            # No packets or invalid packets
            return

        pcap_f.raise_exceptions = False

        pcap_f.tcp = TCPPacketStreamer(pcap_f, self.readers_httpreplay)

        for hosts, ts, protocol, sent, receive in pcap_f.process():
            packet = NetworkData()
            packet.protocol = protocol
            packet.timestamp = ts

            if hosts >= 4:
                packet.src = hosts[0]
                packet.sport = hosts[1]
                packet.dst = hosts[2]
                packet.dport = hosts[3]

            if protocol in handlers:
                p = handlers[protocol](packet, sent, receive)
                log.debug("HTTPREPLAY-PACKET: %s", repr(p))
                self.packets.append(p)

    def _add_pcap_header(self, data):
        return io.BytesIO(self.pcap_header + data)

    def filter_packets(self):

        filters = [
            self._filter_packets_dpkt,
            self._filter_packets_httpreplay
        ]

        with open(self.pcap_path, "rb") as fp:

            # Read the Pcap header so it can be used later when reading
            # the pcap in chunks
            if self.pcap_header is None and self.file_offset == 0:
                self.pcap_header = fp.read(24)
                fp.seek(0)

            pcap_data = None
            if self.file_offset != 0:
                fp.seek(self.file_offset)
                pcap_data = self._add_pcap_header(fp.read())

            for filter in filters:

                if pcap_data is None:
                    fp.seek(self.file_offset)
                    filter(fp)
                else:
                    pcap_data.seek(0)
                    filter(pcap_data)

            self.file_pos = fp.tell()


class ElasticNetwork(Auxiliary):

    def _store_bulk_es(self, collection):
        helpers.bulk(self.es, collection)
        log.debug("Stored set of filtered packets in Elasticsearch")

    def _run_filters(self):
        pfilter = PacketFilter(self.pcap_path, file_offset=self.pcap_offset,
                               pcap_glob_header=self.pcap_header)
        pfilter.filter_packets()
        if self.pcap_offset == 0:
            self.pcap_header = pfilter.pcap_header

        self.pcap_offset = pfilter.file_pos

        current = 0

        log.debug(
            "Preparing extracted packets for bulk submission to Elasticsearch")
        while current < len(pfilter.packets):
            count = 0
            bulk_packets = []
            # Use 'current' to keep track of current packet
            # Needed to continue after breaking and submitting
            for n in range(current, len(pfilter.packets)):
                packet = json.loads(pfilter.packets[n].get_json("packet",
                                                                "packet",
                                                                self.task.experiment_id,
                                                                self.task.id))
                bulk_packets.append(packet)
                count += 1
                current += 1
                if count >= self.max_per_bulk:
                    break

            if len(bulk_packets) > 0:
                self._store_bulk_es(bulk_packets)

    def _run_thread(self):

        while self.running:
            # Start with a sleep to let TCPdump collect some traffic first
            log.debug("Waiting 30 seconds to check PCAP..")
            time.sleep(30)

            if not self.running:
                break

            if not os.path.exists(self.pcap_path):
                log.error("Pcap does not exist in path %s", self.pcap_path)
                continue

            self._run_filters()

    def start(self):
        log.info("ElasticNetwork auxiliary module started")

        self.running = True
        self.pcap_path = ""
        self.pcap_offset = 0
        self.max_per_bulk = 250
        self.pcap_header = None
        self.es = None

        conf = Config("auxiliary")
        es_server = str(conf.elasticnetwork.elasticsearch_server)

        if es_server is None:
            log.error("Missing elasticsearch server in auxiliary config")
            return

        Elasticsearch("http://%s" % es_server, timeout=30)

        self.pcap_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                      str(self.task.id), "dump.pcap")
        th = threading.Thread(target=self._run_thread)
        th.start()

    def stop(self):
        self.running = False
        # Be sure to filter the latest collected packets on stop
        self._run_filters()
        log.info("ElasticNetwork auxiliary module stopped")
