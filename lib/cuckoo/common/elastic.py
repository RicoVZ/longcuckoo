from elasticsearch import Elasticsearch

from lib.cuckoo.common.config import Config

class Elastic(object):
    def __init__(self):
        conf = Config("reporting")
        es_server = conf.elasticsearch.elasticsearch_server
        self.es = Elasticsearch("http://%s" % es_server, timeout=30)

    def search(self, match=None,body=None, size=10000, fields="*"):

        if body is None:
            body = {
                "query": {
                    "bool": {
                        "must": []
                    }
                }
            }
            for key,value in match.iteritems():
                match = {key: value}
                body["query"]["bool"]["must"].append({"term": match})
        else:
            body=body

        results = self.es.search(
            index="packet",
            doc_type="packet",
            body=body,
            _source_include=fields,
            size=size
        )

        return results

    def filter_source(self, results, keep_id=False):

        filtered_results = []

        for result in results["hits"]["hits"]:

            if keep_id:
                result["_source"]["id"] = result["_id"]

            filtered_results.append(result["_source"])

        return filtered_results

    def get_new_streams(self, exp_id, offset=""):
        results = self.search(
            match={"exp_id": exp_id}
        )

        return results

    def get_hostname_ip(self, ip, exp_id):

        results = self.es.search(
            index="packet",
            doc_type="packet",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"protocol":"dns"}},
                            {"term": {"dns_answer.data": ip}},
                            {"term": {"exp_id": exp_id}}
                        ]

                    }
                }
            },
            _source_include="*",
            size=1000
        )

        return results

    def store_heartbeats_experiment(self, stream_sets, mergable_info, exp_id):

        heartbeats = {}
        for merge_dst in mergable_info:
            best_match = mergable_info[merge_dst]["best_match"]
            matches = mergable_info[merge_dst]["matches"]

            if best_match not in heartbeats:

                heartbeat = {
                    "dst": best_match,
                    "stream_keys": [
                        s_key.get("id") for s_key in stream_sets[best_match]
                    ],
                    "likely": []
                }

                heartbeats[best_match] = heartbeat

            likely_related = {
                "dst": merge_dst,
                "matches": matches,
                "stream_keys": [
                    ls_key.get("id") for ls_key in stream_sets[merge_dst]
                ]
            }

            heartbeats[best_match]["likely"].append(likely_related)

        body = {
                "heartbeats": [
                    suspect_sets for dst, suspect_sets in heartbeats.iteritems()
                ]
        }

        self.es.index(
            index="heartbeats",
            doc_type="heartbeats",
            id=exp_id,
            body=body
        )
