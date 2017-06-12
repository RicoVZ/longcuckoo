import urllib
import urllib2
import time
import random

from threading import Thread


class Traffic(object):
    def __init__(self):

        self.agent = ""

        self.interval = 60
        self.rand_interval = False
        self.rand_min = 0
        self.rand_max = 60

        self.url = None
        self.get_params = None
        self.method = "GET"
        self.post_data = None

        self.run = True

        self.max_run_time = -1
        self.run_time = 0
        self.first_run = True

    def _do_request(self):

        try:
            print("Sending message to: %s" % self.url)
            if self.get_params is not None:
                url = "%s%s" % (self.url, self.get_params)
            else:
                url = self.url

            if self.method == "POST" and self.post_data is not None:
                request_data = urllib.urlencode(self.post_data)
                request = urllib2.Request(url, request_data)

            else:
                request = urllib2.Request(url)

            print("URL: %s" % url)
            request.add_header("User-agent", self.agent)
            response = urllib2.urlopen(request)
            response.read()

        except Exception as e:
            print("Error %s" % e)

    def _start_traffic(self):

        if self.url is None:
            return

        while self.run and not self._max_reached():
            self.first_run = False
            self._do_request()

            if self._max_reached():
                break

            if self.rand_interval:
                wait = random.randint(self.rand_min, self.rand_max)
            else:
                wait = self.interval

            time.sleep(wait)
            self.run_time += wait

    def _max_reached(self):

        if self.max_run_time < 0:
            return False

        if self.max_run_time == 1 and not self.first_run:
            return True

        if self.run_time >= self.max_run_time:
            return True

        return False

    def start(self):
        run_thread = Thread(target=self._start_traffic)
        run_thread.start()

    def stop(self):
        self.run = False


class MalwareActions(object):
    def __init__(self):
        self.name = ""

    def init(self):
        pass

    def actions(self):
        pass

    def _run_thread(self):
        self.actions()

    def start(self):
        self.init()
        run_thread = Thread(target=self._run_thread)
        run_thread.start()


class Malware(MalwareActions):

    def init(self):
        self.agents = [
            "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) Chrome/55.0.3029.110 Safari/537.36"
        ]

        self.urls = [
            "http://www.axlflathotel.be/",
            "http://www.skyandtelescope.com/",
            "http://homemail.info/",
            "http://cbcse.org/",
            "http://devinit.org/"
        ]

        self.params = [
            "reporter.php?item=199&file=no&page=somepage",
            "help.php?circle=998894&uuid=PLDTOSTI243&url=none&eula=no&os=win7x64",
            "file.php?cheese=yes&options=one&country=NL&stuff=9845",
            "other.php?random=243892&family=office32",
            "index.php?square=yes&paper=854&uuid=UASD91Q&watch=off&coin=false&destp=7123&os=win10x64&ip=127.0.0.1"
        ]


    def actions(self):
        traffic = Traffic()
        traffic.rand_interval = True
        traffic.rand_min = 20
        traffic.rand_max = 140
        started = False

        count = 0
        for url in self.urls:
            traffic.url = url
            traffic.get_params = self.params[count]
            traffic.agent = self.agents[count]
            if not started:
                traffic.start()
            time.sleep(3600)
            count += 1

        traffic.stop()

if __name__ == "__main__":
    m = Malware()
    m.start()