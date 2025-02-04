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
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient

class CheckNoOutboundConnections(AgentVmTest):
    """
    Verifies that there is no outbound connectivity on the test VM.
    """
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self.__distro: str = None

    @property
    def distro(self) -> str:
        if self.__distro is None:
            raise Exception("The distro has not been initialized")
        return self.__distro

    def run(self):
        # This script is executed on the test VM. It tries to connect to a well-known DNS server (DNS is on port 53).
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
            self.__distro = ssh_client.get_distro()
            log.info("Distro: %s", self.distro)
        except Exception as e:
            log.warning("Could not determine the distro (setting to UNKNOWN): %s", e)
            self.__distro = "UNKNOWN"

        try:
            log.info("Verifying that there is no outbound connectivity on the test VM")
            ssh_client.run_command("pypy3 -c '{0}'".format(script.replace('"', '\"')))
            log.info("There is no outbound connectivity, as expected.")
        except CommandError as e:
            if e.exit_code == 1 and "There is outbound connectivity" in e.stderr:
                fail("There is outbound connectivity on the test VM, the custom ARM template should not allow it")
            else:
                raise Exception(f"Unexpected error while checking outbound connectivity on the test VM: {e}")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            #
            # RHEL 8.2 uses a very old Daemon (2.3.0.2) that does not create the 'ACCEPT DNS' rule. Even with auto-update enabled, the rule is not created for this test, since outbound connectivity is disabled
            # and attempts to get the VM Artifacts Profile blob fail after a long timeout (which prevents the self-update Agent to create the rule before the test starts running). Then, this message is
            # expected and should be ignored.
            #
            #   2025-01-16T09:30:54.048522Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['ACCEPT DNS'] due to: ['']), will reset them. Current state:
            #   ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner 0 -j ACCEPT
            #   ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP
            #
            {
                'message': r"The permanent firewall rules for Azure Fabric are not setup correctly.*The following rules are missing: \['ACCEPT DNS'\]",
                'if': lambda _: self.distro == 'redhat_82'
            }
        ]

if __name__ == "__main__":
    CheckNoOutboundConnections.run_from_command_line()

