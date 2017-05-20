import fnmatch
import urlparse


class Summarize(object):

    def __init__(self, networkstream=None, summary=None):
        self.stream = networkstream
        self.summary = summary

    def update_summary(self, summary, stream):
        pass


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
        "uri_dir": {"default": 10}
    }

    # The minimum amount of matches for a merge
    min_matches = 2
    min_score = 10

    def __init__(self):
        self.summaries = {}
        self.handlers = {
            "http": SummarizeHTTP()
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

    def get_merge_info(self, stream_sets):
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

            if best_match is not None and len(matches) >= self.min_matches \
                    and highest >= self.min_score:
                best_matches.append(best_match)

                mergables[compare_dst] = {
                    "best_match": best_match,
                    "matches": matches,
                    "score": highest
                }

            #print("Best match(%s) for: %s is -> %s. Matches: %s" % (highest, compare_dst, best_match, matches))

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
                            if fnmatch.fnmatch(value, spec_str):
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


class SummarizeHTTP(Summarize):
    """"
    Updates a given summary with the extracted metadata from a HTTP
    network stream
    """

    def update_summary(self, summary, stream):

        self.summary = summary
        self.stream = stream

        self.read_url_info()


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
