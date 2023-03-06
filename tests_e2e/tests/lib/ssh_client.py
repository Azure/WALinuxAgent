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
import re

from pathlib import Path

from tests_e2e.tests.lib import shell
from tests_e2e.tests.lib.retry import retry_ssh_run


class SshClient(object):
    def __init__(self, ip_address: str, username: str, private_key_file: Path, port: int = 22):
        self._ip_address: str = ip_address
        self._username: str = username
        self._private_key_file: Path = private_key_file
        self._port: int = port

    def run_command(self, command: str, use_sudo: bool = False) -> str:
        """
        Executes the given command over SSH and returns its stdout. If the command returns a non-zero exit code,
        the function raises a RunCommandException.
        """
        if re.match(r"^\s*sudo\s*", command):
            raise Exception("Do not include 'sudo' in the 'command' argument, use the 'use_sudo' parameter instead")

        destination = f"ssh://{self._username}@{self._ip_address}:{self._port}"

        # Note that we add ~/bin to the remote PATH, since Python (Pypy) and other test tools are installed there.
        # Note, too, that when using sudo we need to carry over the value of PATH to the sudo session
        sudo = "sudo env PATH=$PATH PYTHONPATH=$PYTHONPATH" if use_sudo else ''
        return retry_ssh_run(lambda: shell.run_command([
            "ssh", "-o", "StrictHostKeyChecking=no", "-i", self._private_key_file, destination,
            f"if [[ -e ~/bin/set-agent-env ]]; then source ~/bin/set-agent-env; fi; {sudo} {command}"]))

    @staticmethod
    def generate_ssh_key(private_key_file: Path):
        """
        Generates an SSH key on the given Path
        """
        shell.run_command(
            ["ssh-keygen", "-m", "PEM", "-t", "rsa", "-b", "4096", "-q", "-N", "", "-f", str(private_key_file)])

    def get_architecture(self):
        return self.run_command("uname -m").rstrip()

    def copy_to_node(self, local_path: Path, remote_path: Path, recursive: bool = False) -> None:
        """
        File copy to a remote node
        """
        self._copy(local_path, remote_path, remote_source=False, remote_target=True, recursive=recursive)

    def copy_from_node(self, remote_path: Path, local_path: Path, recursive: bool = False) -> None:
        """
        File copy from a remote node
        """
        self._copy(remote_path, local_path, remote_source=True, remote_target=False, recursive=recursive)

    def _copy(self, source: Path, target: Path, remote_source: bool, remote_target: bool, recursive: bool) -> None:
        if remote_source:
            source = f"{self._username}@{self._ip_address}:{source}"
        if remote_target:
            target = f"{self._username}@{self._ip_address}:{target}"

        command = ["scp", "-o", "StrictHostKeyChecking=no", "-i", self._private_key_file]
        if recursive:
            command.append("-r")
        command.extend([str(source), str(target)])

        shell.run_command(command)

    def copy(self, local_path: Path, remote_path: Path):
        """
        Copy file from local to remote machine
        """
        destination = f"{self._username}@{self._ip_address}:{remote_path}"
        shell.run_command(["scp", "-o", "StrictHostKeyChecking=no", "-i", self._private_key_file, local_path, destination])
