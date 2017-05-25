import logging
import threading
import time

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.elastic import Elastic
from lib.cuckoo.common.hbfilters import FilterHandler
from lib.cuckoo.common.summarize import SummarizeHandler

log = logging.getLogger(__name__)


class FindHeartbeat(Auxiliary):

    def _run_thread(self):

        # Retrieve old ES ids before running. We do this so they can be
        # updated if they have changed
        self.stored_previous = self.es.get_heartbeat_ids_exp(
            self.task.experiment_id
        )

        while self.running:
            log.debug("Waiting 3 minutes for traffic to be collected")
            time.sleep(180)

            if not self.running:
                break

            self._find_heartbeat()


    def _group_by_dst(self, all_data):
        """"
        Group all ES network data results by destination IP
        """

        host_traffic = {}

        for result in all_data:

            dst = result["dst"]
            if dst not in host_traffic:
                host_traffic[dst] = [result]
            else:
                host_traffic[dst].append(result)

        return host_traffic

    def _find_heartbeat(self):
        # Retrieve all network data such that heartbeats with
        # a lot of time between them can also be found.

        hb_suspects = self.es.filter_source(
            self.es.get_new_streams(self.task.experiment_id),
            keep_id=True
        )
        hb_suspects = self._group_by_dst(hb_suspects)

        # Use filters to remove any unwanted streams
        self.filter_handler.filter_streams(hb_suspects)

        self.summarize_handler.summarize_stream_sets(hb_suspects)
        mergables = self.summarize_handler.get_merge_info()

        self.stored_previous = self.es.store_heartbeats_experiment(
            hb_suspects, mergables,
            self.task.experiment_id, self.stored_previous
        )

    def start(self):
        log.info("FindHeartbeat auxiliary module started")

        self.running = True
        self.es = None
        self.summarize_handler = SummarizeHandler()
        self.filter_handler = FilterHandler(self.task.experiment_id)
        self.stored_previous = []

        conf = Config("auxiliary")

        if conf.elasticnetwork.enabled == "no":
            log.error("FindHeartbeat module cannot be used if ElasticNetwork"
                      " module is disabled")
            return

        self.es = Elastic()

        th = threading.Thread(target=self._run_thread)
        th.start()

    def stop(self):
        self.running = False
        self._find_heartbeat()
        log.info("FindHeartbeat auxiliary module stopped")
