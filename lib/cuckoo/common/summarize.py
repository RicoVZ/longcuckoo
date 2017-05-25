import fnmatch
import urlparse


class Summarize(object):
    transport_protocol = None

    def __init__(self, networkstream=None, summary=None):
        self.stream = networkstream
        self.summary = summary
        self.handlers = {}
        self.init()

    def update_summary(self, summary, stream):
        self.summary = summary
        self.stream = stream

        for name, handler in self.handlers.iteritems():
            if name in self.stream:
                handler()

    def init(self):
        pass

    def add_to_summary(self, get_key, data, summary_key):
        """"
        Add the value of get_key in data to the current summary
        under the name of summary_key, if value is not None
        """
        value = data.get(get_key)
        if value is not None and value is not "":
            self.summary.add_value(summary_key, str(value))


class SummarizeHandler(object):
    """"
    Creates and stores summaries and uses them to merge
    network stream sets based on summary comparison scores
    """

    # The weights for each type of metadata
    # special cases can be created by adding the key 'special'
    # The wildcards * and ? can be used in special cases
    scores = {
        "get_params": {"default": 2},
        "uri_end": {
            "default": 5,
            "special": {
                "*.php": 20,
                "*.exe": 50,
                "*.bin": 50,
                "*.dll": 50
            }
        },
        "uri_contains_file": {"default": 1},
        "uri_exts": {"default": 2},
        "uri_dir": {"default": 10},
        "post_field": {"default": 15},
        "num_post_fields": {"default": 10},
        "num_get_params": {"default": 2},
        "tcp_dport": {
            "default": 50,
            "special": {
                80: 1,
                443: 1
            }
        },
        "http_host": {"default": 100},
        "content_type_sent": {"default": 10},
        "user_agent": {"default": 50},
        "user_agent_browser": {
            "default": 1,
            "special": {
                False: 20
            }
        },
        "tcp_len_sent": {"default": 10},
        "tcp_len_recv": {"default": 10},
        "http_len_sent": {
            "default": 10,
            "special": {
                0: 1
            }
        },
        "http_len_recv": {"default": 10}

    }

    # The minimum amount of matches for a merge
    min_matches = 2
    min_score = 10

    def __init__(self):
        self.summaries = {}
        self.handlers = {
            "http": SummarizeHTTP(),
            "tcp": SummarizeTCP()
        }

    def summarize_stream_sets(self, streams_sets):
        """"
        Create a summary of each stream in stream_sets
        """

        for dst in streams_sets:

            if dst in self.summaries:
                existing_dst_summary = self.summaries[dst]
                if len(streams_sets[dst]) == existing_dst_summary.num_streams:
                    continue

            new_summary = Summary()
            new_summary.num_streams = len(streams_sets[dst])
            new_summary.dst = dst
            self.summaries[dst] = new_summary

            for stream in streams_sets[dst]:

                if stream["protocol"] in self.handlers:
                    handler = self.handlers[stream["protocol"]]
                    handler.update_summary(new_summary, stream)

                    # If the protocol has a transport layer protocol
                    # use the handler to extract information for this layer
                    if handler.transport_protocol is not None:
                        t_handler = self.handlers[handler.transport_protocol]
                        t_handler.update_summary(new_summary, stream)

            print(new_summary.summary)

    def get_merge_info(self):
        """"
        Finds the best match for each stream to be merged to and
        returns a dictionary of streams to be merged and the found matches
        between the to be merged streams
        """

        # Contains all data to perform a merge
        # the data of the key will be merge into the best match
        mergables = {}

        # Contains all destinations deemed a best match
        best_matches = []

        for compare_dst, compare_summary in self.summaries.iteritems():

            # Don't let a best match be merged into
            # another set. If a matching set is found, it will automatically
            # be merged into this one.
            if compare_dst in best_matches:
                continue

            highest = 0
            best_match = None
            matches = None
            for to_dst, to_summary in self.summaries.iteritems():

                # Skip if comparing to self or if the current dst was
                # already deemed a best match at an earlier compare
                if to_dst == compare_dst or to_dst in mergables:
                    continue

                result = self.calc_score_summary(compare_summary, to_summary)
                score = result[0]

                if score > highest:
                    highest = score
                    best_match = to_dst
                    matches = result[1]

            # print("Best match(%s) for: %s is -> %s. Matches: %s" % (highest, compare_dst, best_match, matches))
            if best_match is not None and len(matches) >= self.min_matches \
                    and highest >= self.min_score:
                best_matches.append(best_match)

                mergables[compare_dst] = {
                    "best_match": best_match,
                    "matches": matches,
                    "score": highest
                }

        return mergables

    def cleanup_summaries(self, dsts):
        """"
        Delete the given list of summaries from stored summaries
        """

        for dst in dsts:
            del self.summaries[dst]

    def calc_score_summary(self, summary, compare_to):
        """
        Compares first summary to second summary and returns a
        tuple containing a score and the matches fields and values
        """

        score = 0
        matches = []

        for field in summary.summary:
            compare_data = compare_to.summary.get(field)

            if compare_data is None:
                continue

            for value in summary.summary[field]:
                if value in compare_data:

                    special = self.scores[field].get("special")
                    if special is not None:
                        for spec_str in special:
                            if fnmatch.fnmatch(str(value), str(spec_str)):
                                score += special[spec_str]
                    else:
                        score += self.scores[field]["default"]

                    matches.append({"match_type": field, "value": value})

        return score, matches


class Summary(object):
    """
    A summary contains all unique metadata values for a set of streams.
    A new summary should be created for each network destination
    """

    def __init__(self):
        self.num_streams = 0
        self.dst = None
        self.summary = {}

    def add_value(self, key, value):

        if key in self.summary:
            self.summary[key].add(value)
        else:
            self.summary[key] = set([value])


class SummarizeTCP(Summarize):
    def init(self):
        self.handlers = {
            "dport": self.read_dport,
            "len_sent": self.read_len_sent,
            "len_recv": self.read_len_received
        }

    def read_dport(self):
        dport = self.stream.get("dport")

        if dport is not None:
            self.summary.add_value("tcp_dport", str(dport))

    def read_len_sent(self):
        if self.stream.get("protocol") == "tcp":
            len_sent = self.stream.get("len_sent")

            if len_sent is not None:
                self.summary.add_value("tcp_len_sent", str(len_sent))

    def read_len_received(self):
        if self.stream.get("protocol") == "tcp":
            len_recv = self.stream.get("len_recv")

            if len_recv is not None:
                self.summary.add_value("tcp_len_recv", str(len_recv))


class SummarizeHTTP(Summarize):
    """"
    Updates a given summary with the extracted metadata from a HTTP
    network stream
    """

    browser_strings = [
        "Chrome", "Firefox", "Safari", "MSIE",
        "Opera", "Chromium"
    ]

    transport_protocol = "tcp"

    def init(self):
        self.handlers = {
            "uri_sent": self.read_url_info,
            "body_sent": self.read_body_sent,
            "len_sent": self.read_len_sent,
            "len_recv": self.read_len_received,
            "headers_sent": self.read_headers_sent
        }

    def read_len_sent(self):
        self.add_to_summary("len_sent", self.stream, "http_len_sent")

    def read_len_received(self):
        self.add_to_summary("len_recv", self.stream, "http_len_recv")

    def read_url_info(self):
        """"
        Collects metadata from url
        """

        headers_sent = self.stream.get("headers_sent")
        if headers_sent is not None:
            host = headers_sent.get("host", self.stream["dst"])

        uri = self.stream.get("uri_sent")
        url = "http://%s%s" % (host, uri)
        parsed_url = urlparse.urlsplit(url)
        get_params = urlparse.parse_qsl(parsed_url.query)

        len_params = len(get_params)
        if len_params > 0:
            self.summary.add_value("num_get_params", str(len_params))

        for key, value in get_params:
            self.summary.add_value("get_params", key)

        # get last part of uri
        parts = filter(None, parsed_url.path.rsplit("/", 1))

        if len(parts) > 0:
            uri_end = parts[-1]
        else:
            uri_end = "/"

        self.summary.add_value("uri_end", uri_end)

        if len(uri_end) > 1 and "." in uri_end:
            self.summary.add_value("uri_contains_file", True)
            self.summary.add_value("uri_exts", uri_end.split(".", 1)[1])

        if len(parts) > 1:
            self.summary.add_value("uri_dir", parts[0])

    def read_body_sent(self):

        # retrieve POST fields if present
        body = self.stream.get("body_sent")

        if body is None or body == "":
            return

        post_data = body.split("&")

        num_fields = len(post_data)
        if num_fields < 1:
            return

        self.summary.add_value("num_post_fields", str(num_fields))

        for value in post_data:
            post_field = filter(None, value.split("=", 1))
            if len(post_field) > 0:
                self.summary.add_value("post_field", post_field[0])

    def read_headers_sent(self):

        headers_sent = self.stream.get("headers_sent")

        if headers_sent is None:
            return

        self.add_to_summary("host", headers_sent, "http_host")
        self.add_to_summary("content-type", headers_sent, "content_type_sent")

        user_agent = headers_sent.get("user-agent")
        if user_agent is not None:
            self.summary.add_value("user_agent", user_agent)
            self.summary.add_value(
                "user_agent_browser", self._is_browser(user_agent)
            )

    def _is_browser(self, user_agent):
        """
        Checks if strings used in common desktop browser exist
        in the user agent. If so, it concludes that the user_agent
        if from a browser
        """

        is_browser = False
        for browser_str in self.browser_strings:
            if browser_str in user_agent:
                is_browser = True
                break

        return is_browser
