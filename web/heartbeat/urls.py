# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^(?P<exp_id>\d+)$", "heartbeat.views.index"),
    url(r"^(?P<exp_id>\d+)/(?P<dst>.+)$", "heartbeat.views.heartbeats"),
    url(r"^show/(?P<exp_id>\d+)/(?P<dst>.+)/(?P<related_dst>.+)/(?P<stream_id>\d+)/$", "heartbeat.views.show_network_streams"),
    url(r"^stream/(?P<stream_key>.+)/$", "heartbeat.views.view_stream"),
)
