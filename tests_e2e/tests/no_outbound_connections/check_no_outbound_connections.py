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
from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


class CheckNoOutboundConnections(AgentTest):
    """
    """
    def run(self):
        script: str = """
import socket, sys

try:
    socket.setdefaulttimeout(5)
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
except socket.timeout:
    print("No outbound connectivity [expected]")
    exit(0)
print("There is outbound connectivity [unexpected: the custom ARM template should not allow it]", file=sys.stderr)
exit(1)
"""
        ssh_client: SshClient = self._context.create_ssh_client()
        try:
            log.info("Verifying that there is no outbound connectivity on the test VM")
            ssh_client.run_command("pypy3 -c '{0}'".format(script.replace('"', '\"')))
            log.info("There is no outbound connectivity, as expected.")
        except CommandError as e:
            if e.exit_code == 1 and "There is outbound connectivity" in e.stderr:
                fail("There is outbound connectivity on the test VM, the custom ARM template should not allow it")
            else:
                raise Exception(f"Unexpected error while checking outbound connectivity on the test VM: {e}")


if __name__ == "__main__":
    CheckNoOutboundConnections.run_from_command_line()

