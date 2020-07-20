#!/usr/bin/env python3

import requests
from cortexutils.analyzer import Analyzer

SERVICES = "windows-user-login-ips"
USER_AGENT = "vz-cortex/elasticsearch-1.0"
USER_LOGON_EVENT_CODE = 4624
MAX_RESULT_SIZE = 50
DEFAULT_HOURS = 12


class Elasticsearch(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # user configurable settings
        self.url = self.get_param("config.es_url", None, "Missing ES URL")
        self.username = self.get_param(
            "config.es_username", None, "Missing ES username"
        )
        self.password = self.get_param(
            "config.es_password", None, "Missing ES password"
        )
        self.index = self.get_param("config.es_search_index", None, "Missing ES index")
        self.hours = self.get_param("config.es_hours", DEFAULT_HOURS)
        self.user_agent = self.get_param("config.user_agent", USER_AGENT)
        self.service = self.get_param("config.service", None, "Service is missing")
        self.data = self.get_data()

        self.headers = {
            "User-Agent": self.user_agent,
            "Accepts": "application/json",
            "Content-Type": "application/json",
        }

        if self.hours < 0:
            self.error("Hours must be greater than 0.")

        if self.service not in SERVICES:
            self.error("bad service")

    def run(self):
        if self.service == "vpn-logons-ips":
            pass
        if self.service == "windows-user-login-ips":
            # search for user logons
            data = {
                "_source": [
                    "source.ip",
                    "agent.hostname",
                    "winlog.event_data.LogonType",
                    "@timestamp",
                ],
                "size": MAX_RESULT_SIZE,
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "user.name"}},
                            {"exists": {"field": "agent.hostname"}},
                            {"match": {"event.code": "4624"}},
                            {"match": {"user.name": "joe.vasquez"}},
                        ],
                        "filter": {
                            "range": {"@timestamp": {"gte": f"now-{self.hours}h"}}
                        },
                    }
                },
            }

            response = requests.get(
                self.url + "/" + self.index + "/_search",
                headers=self.headers,
                auth=(self.username, self.password),
                json=data,
            )

            if response.status_code == requests.codes.ok:
                json_data = response.json()

                data = dict()
                data["ips"] = set()
                data["logon_info"] = list()
                for hit in json_data["hits"]["hits"]:
                    ip = hit["_source"]["source"]["ip"]
                    data["ips"].add(ip)
                    data["logon_info"].append(
                        {
                            "server": hit["_source"]["agent"]["hostname"],
                            "logon_type": hit["_source"]["winlog"]["event_data"][
                                "LogonType"
                            ],
                            "timestamp": hit["_source"]["@timestamp"],
                            "ip": ip,
                        }
                    )
                data["total_ips"] = len(data["ips"])
                data["ips"] = list(data["ips"])

                self.report(data)

            else:
                self.error(
                    f"Unable to complete request. status code: {response.status_code}"
                )


if __name__ == "__main__":
    Elasticsearch().run()
