#!/usr/bin/env python3

import requests
from cortexutils.analyzer import Analyzer

SERVICES = ("redirects",)
USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:77.0) Gecko/20190101 Firefox/77.0"


class HTTPInfo(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # user configurable settings
        self.user_agent = self.get_param("config.user_agent", USER_AGENT,)

        self.service = self.get_param("config.service", None, "Service is missing")

        self.data = self.get_data()

        self.headers = {
            "User-Agent": self.user_agent,
        }

        if self.service not in SERVICES:
            self.error("bad service")

        self.proxies = self.get_param("config.proxy", None)

    def artifacts(self, raw):
        artifacts = []
        if self.service == "redirects":
            for key, value in raw.items():
                artifacts.append(self.build_artifact("url", value["url"]))
        return artifacts

    def run(self):
        if self.service == "redirects":
            res = requests.head(
                self.data,
                allow_redirects=True,
                headers=self.headers,
                proxies=self.proxies,
            )

            history = {}
            i = 0
            for item in res.history:
                history[i] = {
                    "url": item.url,
                    "status_code": item.status_code,
                    "headers": dict(item.headers),
                }
                i += 1

            history[i] = {
                "url": res.url,
                "status_code": res.status_code,
                "headers": dict(res.headers),
            }

            self.report(history)

    def summary(self, raw):
        if self.service == "redirects":
            count = len(raw.get("history", []))
            if count == 0:
                level = "safe"
            else:
                level = "suspicious"
            return {
                "taxonomies": [
                    self.build_taxonomy(level, "HTTP_INFO", "Redirects", count)
                ]
            }
        return {}


if __name__ == "__main__":
    HTTPInfo().run()
