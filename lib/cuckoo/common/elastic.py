from elasticsearch import Elasticsearch, helpers

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

    def store_heartbeats_experiment(self, stream_sets, mergable_info, exp_id,
                                    previous_ids):

        heartbeats = {}
        ids_stored = []

        for dst, stream_set in stream_sets.iteritems():

            if dst not in mergable_info:

                id = "%s-%s" % (exp_id, dst)
                ids_stored.append(id)

                heartbeat = {
                    "_index": "heartbeats",
                    "_type": "heartbeats",
                    "_id": id,
                    "exp_id": exp_id,
                    "dst": dst,
                    "stream_keys": [
                        s_key.get("id") for s_key in stream_sets[dst]
                        ],
                    "likely": []
                }

                heartbeats[dst] = heartbeat

        for merge_dst in mergable_info:
            best_match = mergable_info[merge_dst]["best_match"]
            matches = mergable_info[merge_dst]["matches"]

            likely_related = {
                "dst": merge_dst,
                "matches": matches,
                "stream_keys": [
                    ls_key.get("id") for ls_key in stream_sets[merge_dst]
                ]
            }

            heartbeats[best_match]["likely"].append(likely_related)

        body = [suspect_sets for dst, suspect_sets in heartbeats.iteritems()]

        helpers.bulk(self.es, body)

        # Check if any heartbeats that were previously stored are now
        # merged into another destination. Removed those if found
        diff = set(previous_ids) - set(ids_stored)
        if len(diff) > 0:
            print("deleting %s " % diff)
            delete = []
            for id in diff:
                delete.append({
                    "_op_type": "delete",
                    "_index": "heartbeats",
                    "_type": "heartbeats",
                    "_id": id
                })

            helpers.bulk(self.es, delete)

        return ids_stored

    def get_last_exp_stream_id(self, exp_id):

        result = self.es.search(
            size=0,
            index="packet",
            doc_type="packet",
            body={
                "query": {
                    "match": {
                        "exp_id": exp_id
                    }
                },
                "aggs" : {
                    "max_id" : {
                        "max" : { "field" : "stream_id" }
                    }
                }
            }
        )

        return result["aggregations"]["max_id"]["value"]

