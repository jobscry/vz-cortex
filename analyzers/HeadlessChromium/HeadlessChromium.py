#!/usr/bin/env python3

import os
import random
import string
import subprocess

from cortexutils.analyzer import Analyzer
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable

SERVICES = ("screenshot",)


class HeadlessChromium(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # user configurable settings
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "TheHive URL missing!"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "TheHive API key missing!"
        )
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


def run(self):
    if self.service == "screenshot":
        letters = string.ascii_letters
        tmp_profile_path = "/tmp/" + "".join(random.choice(letters) for i in range(13))
        command_parts = [
            self.binary_path,
            "--headless",
            "--user-data-dir=" + tmp_profile_path,
            "--window-size=" + self.window_size,
            "--user-agent=" + self.user_agent,
            "--screenshot",
            self.data,
        ]
        completed_process = subprocess.run(command_parts, capture_output=True)
        if b"Written to file screenshot.png" not in completed_process.stdout:
            self.error("Could not create screenshot.")

        filename = os.path.join(self.cwd, "screenshot.png")
        if not os.path.exists(filename):
            self.error("Missing screenshot.")

        api = TheHiveApi(self.thehive_url, self.thehive_apikey)
        file_observable = CaseObservable(
            dataType="file",
            data=[filename,],
            tlp=self.get_param("data.tlp"),
            tags=["screenshot", "png", "parent:" + self.get_param("data.data"),],
            message="retrieved through headless Chromium",
        )
        res = api.create_case_observable(
            self.get_param("data._parent"), file_observable
        )
        self.report({"message": f"{res.status_code} {res.text}"})


if __name__ == "__main__":
    HeadlessChromium().run()
