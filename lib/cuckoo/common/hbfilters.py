import socket
import struct

from elastic import Elastic


class FilterHandler(object):

    def __init__(self, exp_id):
        self.filters = {
            "ip_subnet": FilterPrivateNetworks(),
            "whitelist_domains": FilterDomains(exp_id),
            "insufficient_data": FilterInsufficientData()
        }

    def filter_streams(self, stream_sets):

        delete = set()

        for dst, stream_set in stream_sets.iteritems():

            for filter_name, stream_filter in self.filters.iteritems():
                delete.update(stream_filter.filter(dst, stream_set))

        for dst in delete:
            del stream_sets[dst]


class FilterData(object):

    def __init__(self):
        self.dst = None
        self.stream_set = None

    def filter(self, dst, stream_set):
        return []


class FilterPrivateNetworks(FilterData):

    def filter(self, dst, stream_set):
        """
        Filter out candidates that are part of the whitelisted\
        IPs and IP subnets
        """

        self.dst = dst
        self.stream_set = stream_set

        delete = []

        if self._is_private_ip(dst):
            delete.append(dst)

        return delete

    def _is_private_ip(self, ip):
        """
        Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
        a private network block.
        """

        # Networks IANA reserved
        networks = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "224.0.0.0/4",
            "8.8.8.8/32"
        ]

        for network in networks:
            try:
                ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

                netaddr, bits = network.split("/")

                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - int(bits))) - 1

                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
            except:
                continue

        return False


class FilterDomains(FilterData):

    wl_domains = [
        "microsoft.com",
        "windowsupdate.com",
        "adobe.com",
        "windows.com",
        "msftncsi.com",
        "msn.com"
    ]

    def __init__(self, exp_id):
        FilterData.__init__(self)
        self.ip_hostname = {}
        self.exp_id = exp_id
        self.es = Elastic()

    def filter(self, dst, stream_set):
        """"
        Filter out all candidates that were the result of a domain lookup
        that exists in the domain whitelist.
        """
        self.dst = dst
        self.stream_set = stream_set
        delete = []

        # Update dict of ip hostname combinations
        if self.dst not in self.ip_hostname:
            self._get_hostnames_ip()

        if self._hostname_whitelisted(self.dst):
            delete.append(self.dst)

        return delete

    def _get_hostnames_ip(self):

        results = self.es.filter_source(self.es.get_hostname_ip(self.dst,
                                                                self.exp_id))
        for result in results:
            for ans in result["dns_answer"]:
                if ans["type"] != "A":
                    continue

                answer = ans["data"]

                if answer not in self.ip_hostname:
                    self.ip_hostname[answer] = set([result["dns_query"]])
                else:
                    self.ip_hostname[answer].add(result["dns_query"])

    def _hostname_whitelisted(self, ip):

        if ip in self.ip_hostname:
            hostnames = self.ip_hostname[ip]
            for hostname in hostnames:

                for wl_domain in self.wl_domains:
                    if hostname.endswith(wl_domain):
                        return True

        return False


class FilterInsufficientData(FilterData):

    def filter(self, dst, stream_set):
        """"
        Remove candidates if there is not at least two
        occurances of traffic
        """
        self.dst = dst
        self.stream_set = stream_set
        delete = []

        if len(stream_set) < 2:
            delete.append(dst)

        return delete
