# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys


from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.elastic import Elastic

es = Elastic()

@require_safe
def index(request, exp_id=None):
    es = Elastic()

    results = es.filter_source(es.es.search(
        index="heartbeats",
        doc_type="heartbeats",
        body={
            "query": {
                "match": {
                    "exp_id": exp_id
                }
            }
        }
    ))

    return render_to_response("heartbeat/index.html", {"results": results},
                              context_instance=RequestContext(request))


def heartbeats(request, exp_id=None, dst=None):

    es = Elastic()
    results = es.filter_source(es.es.search(
        index="heartbeats",
        doc_type="heartbeats",
        body={
            "query": {
                "constant_score" : {
                    "filter" : {
                         "bool" : {
                            "must" : [
                                { "term" : { "exp_id" : exp_id } },
                                { "term" : { "dst" : dst } }
                            ]
                        }
                    }
                }
            }
        }
    ))

    if len(results) > 0:
        results = {"results": results[0]}
    else:
        results = {"results": []}

    return render_to_response("heartbeat/heartbeat.html",
                              results,
                              context_instance=RequestContext(request))

def show_network_streams(request, exp_id=None, dst=None, related_dst=None, stream_id=None):
    es = Elastic()

    results = es.filter_source(es.es.search(
        size=10,
        index="packet",
        doc_type="packet",
        body={
            "sort": [
                {
                    "stream_id": "asc"
                }
            ],
            "query": {
                "constant_score": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"term": {"exp_id": exp_id}},
                                {"term": {"dst": related_dst}},
                                {"range": {"stream_id": {"gt": stream_id}}}
                            ]
                        }
                    }
                }
            }
        }
    ), keep_id=True)

    if len(results) >= 10:
        last_id = results[-1]["stream_id"]
    else:
        last_id = None

    info = {
        "parent": dst,
        "exp_id": exp_id,
        "current": related_dst,
        "last_id": last_id
    }

    return render_to_response("heartbeat/streams.html",
                              {"results":  results,
                               "info": info},
                              context_instance=RequestContext(request))


def view_stream(request, stream_key=None):
    es = Elastic()

    results = es.filter_source(es.search(
        match={"_id": stream_key},
        size=1
    ))

    if len(results) > 0:
        results = results[0]
    else:
        results = None

    return render_to_response("heartbeat/viewstream.html",
                              {"results":  results},
                              context_instance=RequestContext(request))
