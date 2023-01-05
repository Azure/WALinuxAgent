#!/usr/bin/env python3

# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from pathlib import Path

from tests_e2e.scenarios.lib import shell


class SshClient(object):
    def __init__(self, ip_address: str, username: str, private_key_file: Path, port: int = 22):
        self._ip_address: str = ip_address
        self._username:str = username
        self._private_key_file: Path = private_key_file
        self._port: int = port

    def run_command(self, command: str) -> str:
        """
        Executes the given command over SSH and returns its stdout. If the command returns a non-zero exit code,
        the function raises a RunCommandException.
        """
        destination = f"ssh://{self._username}@{self._ip_address}:{self._port}"

        return shell.run_command(["ssh", "-o", "StrictHostKeyChecking=no", "-i", self._private_key_file, destination, command])

    @staticmethod
    def generate_ssh_key(private_key_file: Path):
        """
        Generates an SSH key on the given Path
        """
        shell.run_command(["ssh-keygen", "-m", "PEM", "-t", "rsa", "-b", "4096", "-q", "-N", "", "-f", str(private_key_file)])

