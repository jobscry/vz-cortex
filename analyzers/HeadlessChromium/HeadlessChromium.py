#!/usr/bin/env python3

import os
import random
import string
import subprocess
import tempfile
from pathlib import Path
from shutil import copyfileobj
from urllib.parse import urlsplit

import iocextract
from cortexutils.analyzer import Analyzer

SERVICES = ("screenshot", "dom")


class HeadlessChromium(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # user configurable settings
        self.binary_path = self.get_param(
            "config.binary_path", None, "Missing binary path!"
        )
        self.user_agent = self.get_param(
            "config.user_agent",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:77.0) Gecko/20190101 Firefox/77.0",
        )
        x = self.get_param("config.window_size_x", 1920)
        y = self.get_param("config.window_size_y", 2160)

        self.window_size = f"{x},{y}"

        self.cwd = os.getcwd()

        self.data = self.get_data()

        self.service = self.get_param("config.service")
        if self.service not in SERVICES:
            self.error("bad service")

        self.filename = None

        self.proxies = self.get_param("config.proxy", None)

    def get_domain_from_url(self, url: str) -> str:
        domain = urlsplit(url).netloc

        # check for port in url e.g.`test.com:8080`
        if ":" in domain:
            domain = domain.split(":")[0]

        # check for user e.g. "joe@test.com"
        if "@" in domain:
            domain = domain.split("@")[1]

        return domain

    def summary(self, raw):
        return {}

    def artifacts(self, raw):
        if self.filename:
            return [
                self.build_artifact("file", self.filename),
            ]
        else:
            artifacts = []
            raw_str = str(raw)
            raw_str = raw_str.replace('\\"', '"')
            urls = set(iocextract.extract_urls(raw_str))
            ipv4s = set(iocextract.extract_ipv4s(raw_str))
            mail_addresses = set(iocextract.extract_emails(raw_str))

            if urls:
                for u in urls:
                    artifacts.append(self.build_artifact("url", str(u)))
            if ipv4s:
                for i in ipv4s:
                    artifacts.append(self.build_artifact("ip", str(i)))
            if mail_addresses:
                for e in mail_addresses:
                    artifacts.append(self.build_artifact("mail", str(e)))
            return artifacts

    def build_artifact(self, data_type, data, **kwargs):
        if data_type == "file":
            (dst, filename) = tempfile.mkstemp(
                dir=os.path.join(self.job_directory, "output")
            )
            with open(data, "rb") as src:
                copyfileobj(src, open(dst, "wb"))
                kwargs.update(
                    {
                        "dataType": data_type,
                        "file": os.path.basename(filename),
                        "filename": self.get_domain_from_url(self.data)
                        + "-screenshot.png",
                    }
                )
                return kwargs

        else:
            kwargs.update({"dataType": data_type, "data": data})
            return kwargs

    def run(self):
        letters = string.ascii_letters
        tmp_profile_path = "/tmp/" + "".join(random.choice(letters) for i in range(13))
        Path(tmp_profile_path).mkdir(exist_ok=True)

        url = self.data

        if self.service == "screenshot":

            filename = os.path.join(self.cwd, "screenshot.png")
            if os.path.exists(filename):
                Path(filename).unlink()

            command_parts = [
                self.binary_path,
                "--headless",
                "--user-data-dir=" + tmp_profile_path,
                "--window-size=" + self.window_size,
                f'--user-agent="{self.user_agent}"',
                "--screenshot",
            ]

            proxy = self._get_proxy_args(url)
            if proxy is not None:
                command_parts.append(proxy)

            command_parts.append(["--screenshot", url])

            completed_process = subprocess.run(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )

            if not os.path.exists(filename):
                self.error("Missing screenshot. " + completed_process.stderr)
            else:
                self.filename = filename
                self.report({"result": "created screenshot"})
        elif self.service == "dom":
            command_parts = [
                self.binary_path,
                "--headless",
                "--user-data-dir=" + tmp_profile_path,
                f'--user-agent="{self.user_agent}"',
            ]

            proxy = self._get_proxy_args(url)
            if proxy is not None:
                command_parts.append(proxy)

            command_parts.append(["--dump-dom", url])

            completed_process = subprocess.run(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="UTF-8",
            )

            self.report(
                {"html": completed_process.stdout, "stderr": completed_process.stderr,}
            )

    def _get_proxy_args(self, url):
        if self.proxies:
            if url.startswith("https"):
                if "https" in self.proxies:
                    return "--proxy_server=" + self.proxies["https"]
            elif url.startswith("http"):
                if "http" in self.proxies:
                    return "--proxy_server=" + self.proxies["http"]
        return None


if __name__ == "__main__":
    HeadlessChromium().run()
