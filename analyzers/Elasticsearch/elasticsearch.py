#!/usr/bin/env python3

import re

import requests
from cortexutils.analyzer import Analyzer

SERVICES = ("windows-user-login-ips", "cisco-vpn-user-login-ips")
USER_AGENT = "vz-cortex/elasticsearch-1.0"
WINDOWS_SUCCESSFUL_LOGON_EVENT_CODE = 4624
WINDOWS_UNSUCCESSFUL_LOGON_EVENT_CODE = 4625
WINDOWS_SUCCESSFUL_LOGON_TYPES = {
    "2": "Interactive (logon at keyboard and screen of system)",
    "3": "Network (i.e. connection to shared folder on this computer from elsewhere on network)",
    "4": "Batch (i.e. scheduled task)",
    "5": "Service (Service startup)",
    "7": "Unlock (i.e. unnattended workstation with password protected screen saver)",
    "8": 'NetworkCleartext (Logon with credentials sent in the clear text. Most often indicates a logon to IIS with "basic authentication") See this article for more information.',
    "9": 'NewCredentials such as with RunAs or mapping a network drive with alternate credentials.  This logon type does not seem to show up in any events.  If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."',
    "10": "RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)",
    "11": "CachedInteractive (logon with cached domain credentials such as when logging on to a laptop when away from the network)",
}
WINDOWS_UNSUCCESSFUL_LOGON_CODES = {
    "0xC0000064": "user name does not exist",
    "0xC000006A": "user name is correct but the password is wrong",
    "0xC0000234": "user is currently locked out",
    "0xC0000072": "account is currently disabled",
    "0xC000006F": "user tried to logon outside his day of week or time of day restrictions",
    "0xC0000070": "workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)",
    "0xC0000193": "account expiration",
    "0xC0000071": "expired password",
    "0xC0000133": "clocks between DC and other computer too far out of sync",
    "0xC0000224": "user is required to change password at next logon",
    "0xC0000225": "evidently a bug in Windows and not a risk",
    "0xc000015b": "The user has not been granted the requested logon type (aka logon right) at this machine",
}
CISCO_VPN_MESSAGE_ID = "722051"
MAX_RESULT_SIZE = 100
DEFAULT_HOURS = 12
SAFE_IP_COUNT = 2
IGNORE_IPS_SAFE_CHARS = re.compile(r"^[0-9/\.\:,\s]+$")


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

        ignore_ips = self.get_param("config.es_ignore_ips", None)
        if ignore_ips is None:
            self.ignore_ips = []
        else:
            self.ignore_ips = [x.strip() for x in ignore_ips.split(",")]

        if self.service not in SERVICES:
            self.error("bad service")

        self.verify = self.get_param("config.ca_cert_path", True)

        self.proxies = self.get_param("config.proxy", None)

    def summary(self, raw):
        count = raw.get("total_ips", 0)
        if count <= SAFE_IP_COUNT:
            level = "safe"
        else:
            level = "suspicious"

        predicate = "windows-login-ips"
        if self.service == "cisco-vpn-user-login-ips":
            predicate = "cisco-vpn-ips"

        return {"taxonomies": [self.build_taxonomy(level, "ES", predicate, count)]}

    def run(self):
        results = dict()
        must_not = self._build_ignore_ips()

        if self.service == "cisco-vpn-user-login-ips":
            data = {
                "_source": ["user.name", "source.ip", "@timestamp"],
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": MAX_RESULT_SIZE,
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "user.name"}},
                            {"match": {"user.name": self.data}},
                            {"match": {"cisco.asa.message_id": CISCO_VPN_MESSAGE_ID}},
                        ],
                        "filter": {
                            "range": {"@timestamp": {"gte": f"now-{self.hours}h"}}
                        },
                    }
                },
            }

            if must_not is not None:
                data["query"]["bool"]["must_not"] = must_not

            response = requests.get(
                self.url + "/" + self.index + "/_search",
                headers=self.headers,
                auth=(self.username, self.password),
                json=data,
                proxies=self.proxies,
                verify=self.verify,
            )

            if response.status_code != requests.codes.ok:
                self._http_status_error(response.status_code)
            else:
                json_data = response.json()

                results["successful_logon_ips"] = set()
                results["logon_info"] = list()

                for hit in json_data["hits"]["hits"]:
                    ip = hit["_source"]["source"]["ip"]

                    item = {
                        "timestamp": hit["_source"]["@timestamp"],
                        "ip": ip,
                    }
                    results["successful_logon_ips"].add(ip)

                    results["logon_info"].append(item)

                results["successful_logon_ips"] = list(results["successful_logon_ips"])
                results["total_ips"] = len(results["successful_logon_ips"])

        elif self.service == "windows-user-login-ips":
            # search for user logons
            data = {
                "_source": [
                    "source.ip",
                    "agent.hostname",
                    "winlog.event_data.LogonType",
                    "@timestamp",
                    "event.code",
                    "winlog.event_data.SubStatus",
                    "user.name",
                ],
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": MAX_RESULT_SIZE,
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "user.name"}},
                            {"exists": {"field": "agent.hostname"}},
                            {"match": {"user.name": self.data}},
                        ],
                        "should": [
                            {
                                "match": {
                                    "event.code": WINDOWS_SUCCESSFUL_LOGON_EVENT_CODE
                                }
                            },
                            {
                                "match": {
                                    "event.code": WINDOWS_UNSUCCESSFUL_LOGON_EVENT_CODE
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                        "filter": {
                            "range": {"@timestamp": {"gte": f"now-{self.hours}h"}}
                        },
                    }
                },
            }

            if must_not is not None:
                data["query"]["bool"]["must_not"] = must_not

            response = requests.get(
                self.url + "/" + self.index + "/_search",
                headers=self.headers,
                auth=(self.username, self.password),
                json=data,
                proxies=self.proxies,
                verify=self.verify,
            )

            if response.status_code != requests.codes.ok:
                self._http_status_error(response.status_code)
            else:
                json_data = response.json()

                results["successful_logon_ips"] = set()
                results["unsuccessful_logon_ips"] = set()
                results["logon_info"] = list()

                for hit in json_data["hits"]["hits"]:
                    ip = hit["_source"]["source"]["ip"]
                    event_code = hit["_source"]["event"]["code"]

                    item = {
                        "host": hit["_source"]["agent"]["hostname"],
                        "timestamp": hit["_source"]["@timestamp"],
                        "ip": ip,
                        "event_code": event_code,
                    }

                    if event_code == WINDOWS_SUCCESSFUL_LOGON_EVENT_CODE:
                        results["successful_logon_ips"].add(ip)
                        item["outcome"] = "success"

                    else:
                        results["unsuccessful_logon_ips"].add(ip)
                        item["outcome"] = "failure"

                    if "LogonType" in hit["_source"]["winlog"]["event_data"]:
                        logon_type = hit["_source"]["winlog"]["event_data"]["LogonType"]
                        item["logon_type"] = logon_type
                        item["verbose_logon_type"] = WINDOWS_SUCCESSFUL_LOGON_TYPES.get(
                            logon_type, "unknown"
                        )
                    if "SubStatus" in hit["_source"]["winlog"]["event_data"]:
                        substatus = hit["_source"]["winlog"]["event_data"]["SubStatus"]
                        item["substatus"] = substatus
                        item[
                            "verbose_substatus"
                        ] = WINDOWS_UNSUCCESSFUL_LOGON_CODES.get(substatus, "unknown")

                    results["logon_info"].append(item)

                results["successful_logon_ips"] = list(results["successful_logon_ips"])
                results["unsuccessful_logon_ips"] = list(
                    results["unsuccessful_logon_ips"]
                )
                results["total_ips"] = len(results["successful_logon_ips"]) + len(
                    results["unsuccessful_logon_ips"]
                )

        self.report(results)

    def _http_status_error(self, status_code):
        self.error(f"Unable to complete request. Status code: {status_code}")

    def _build_ignore_ips(self):
        if len(self.ignore_ips) == 0:
            return None

        must_not = list()
        for ip in self.ignore_ips:
            if IGNORE_IPS_SAFE_CHARS.match(ip) is None:
                self.error(f"Ignore IP does not match safe characters: {ip}")
            else:
                must_not.append({"match": {"source.ip": ip}})
        return must_not


if __name__ == "__main__":
    Elasticsearch().run()
