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
        self.run = True
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
            "Trickbot 1",
            "Curl/2.0",
            "ZeusReporter",
            "CryptoAPI",
            "Invalid Agent"
        ]

        self.urls = [
            "http://homemail.info",
            "http://cbcse.org",
            "http://devinit.org"
        ]

    def actions(self):
        traffic = Traffic()
        traffic.rand_interval = True
        traffic.rand_min = 20
        traffic.rand_max = 180
        agentcount = 0

        self.noise()

        # do posts
        traffic.method = "POST"
        traffic.url = "http://www.axlflathotel.be/"
        traffic.post_data = {"test1": "adaa", "test2": "89sdf"}
        traffic.agent = self.agents[agentcount]
        traffic.start()
        time.sleep(3600)
        traffic.stop()
        agentcount += 1

        count = 0
        for url in self.urls:
            traffic.method = "GET"
            traffic.url = self.urls[count]
            traffic.agent = self.agents[agentcount]
            if count < 1:
                traffic.start()

            agentcount += 1
            count += 1
            time.sleep(3600)

        traffic.stop()

    def noise(self):
        noise = Traffic()
        noise.agent = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0"
        noise.url = "http://telegraaf.nl"
        noise.interval = 280
        noise.max_run_time = 22000
        noise.start()


if __name__ == "__main__":
    m = Malware()
    m.start()