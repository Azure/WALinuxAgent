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
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentPersistFirewallTest(AgentVmTest):
    """
    This test verifies agent setup persist firewall rules using custom network setup service or firewalld service. Ensure those rules are added on boot and working as expected.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def run(self):
        self._test_setup()
        # Test case 1: After test agent install, verify firewalld or network.setup is running
        self._verify_persist_firewall_service_running()
        # Test case 2: Disable the agent(so that agent won't get started after reboot)
        # perform reboot and ensure firewall rules added on boot even after agent is disabled
        self._disable_agent()
        self._context.vm.restart(wait_for_boot=True, ssh_client=self._ssh_client)
        self._verify_persist_firewall_service_running()
        self._verify_firewall_rules_on_boot("first_boot")
        # Test case 3: Re-enable the agent and do an additional reboot. The intention is to check for conflicts between the agent and the persist firewall service
        self._enable_agent()
        self._context.vm.restart(wait_for_boot=True, ssh_client=self._ssh_client)
        self._verify_persist_firewall_service_running()
        self._verify_firewall_rules_on_boot("second_boot")
        # Test case 4: perform firewalld rules deletion and ensure deleted rules added back to rule set after agent start
        self._verify_firewall_rules_readded()

    def _test_setup(self):
        log.info("Doing test setup")
        output = self._ssh_client.run_command(f"agent_persist_firewall-test_setup {self._context.username}", use_sudo=True)
        log.info(f"Successfully completed test setup\n{output}")

    def _verify_persist_firewall_service_running(self):
        log.info("Verifying persist firewall service is running")
        self._run_remote_test(self._ssh_client, "agent_persist_firewall-verify_persist_firewall_service_running.py", use_sudo=True)
        log.info("Successfully verified persist firewall service is running\n")

    def _verify_firewall_rules_on_boot(self, boot_name):
        log.info("Verifying firewall rules on {0}".format(boot_name))
        self._run_remote_test(self._ssh_client, f"agent_persist_firewall-verify_firewall_rules_on_boot.py --user {self._context.username} --boot_name {boot_name}", use_sudo=True)
        log.info("Successfully verified firewall rules on {0}".format(boot_name))

    def _verify_firewall_rules_readded(self):
        log.info("Verifying firewall rules readded")
        self._run_remote_test(self._ssh_client, "agent_persist_firewall-verify_firewalld_rules_readded.py", use_sudo=True)
        log.info("Successfully verified firewall rules readded\n")

    def _enable_agent(self):
        log.info("Enabling agent")
        output = self._ssh_client.run_command("agent-service enable", use_sudo=True)
        log.info(f"Successfully enabled agent\n{output}")

    def _disable_agent(self):
        log.info("Disabling agent")
        output = self._ssh_client.run_command("agent-service disable", use_sudo=True)
        log.info(f"Successfully disabled agent\n{output}")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            #
            # The test deletes those rules, so the messages are expected
            #
            # 2024-07-30T23:36:35.705717Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['ACCEPT DNS']), will reset them.
            # 2024-07-30T23:37:23.612352Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['ACCEPT']), will reset them.
            # 2024-07-30T23:38:11.083028Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['DROP']), will reset them.
            #
            {
                'message': r"The permanent firewall rules for Azure Fabric are not setup correctly \(The following rules are missing: \[('ACCEPT DNS'|'ACCEPT'|'DROP'|, )+\]\), will reset them.",
                'if': lambda r: r.level == "WARNING"
            }
        ]


if __name__ == "__main__":
    AgentPersistFirewallTest.run_from_command_line()
