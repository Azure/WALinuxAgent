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
from tests_e2e.tests.lib.firewall_utilities import FirewallUtilities


class AgentFirewall(AgentVmTest):
    """
    This test verifies the agent firewall rules are added properly. It checks each firewall rule is present and working as expected.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        FirewallUtilities.skip_test_if_proxy_agent_is_managing_the_wireserver_endpoint(self._ssh_client)

        self._run_remote_test(self._ssh_client, f"agent_firewall-verify_all_firewall_rules.py --user {self._context.username}", use_sudo=True)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            #
            # The test deletes those rules, so the messages are expected
            #
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): The following rules are missing: ['ACCEPT DNS']
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): The following rules are missing: [ACCEPT', 'DROP']
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): The following rules are missing: ['DROP']
            #
            # 2024-07-23T16:24:35.641183Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. The following rules are missing: ['ACCEPT DNS']
            # 2024-07-23T16:26:26.236948Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. The following rules are missing: ['ACCEPT', 'DROP']
            # 2024-07-23T16:28:07.206546Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. The following rules are missing: ['DROP']
            #
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): ['No expression excludes the DNS port'].
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): ['The drop action is missing'].
            # 2024-07-31T13:49:53.309481Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): ["No expression excludes the Agent's UID"].
            #
            # 2024-08-01T23:50:11.607020Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. ['No expression excludes the DNS port'].
            # 2024-08-01T23:51:01.981996Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. ['The drop action is missing'].
            # 2024-08-01T23:52:02.033667Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. ["No expression excludes the Agent's UID"].
            #
            # 2024-09-16T23:22:05.479213Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): There should be exactly one rule in the 'output' chain
            # 2024-09-16T23:22:06.432490Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. There should be exactly one rule in the 'output' chain. Will reset it. Current state:
            {
                'message': r"(The following rules are missing: \[('ACCEPT DNS'|'ACCEPT'|'DROP'|, )+\])"
                           r"|"
                           r"\[('No expression excludes the DNS port'|'The drop action is missing'|\"No expression excludes the Agent's UID\")+\]"
                           r"|"
                           r"\(There should be exactly one rule in the 'output' chain.\)",
                'if': lambda r: r.level == "WARNING"
            }
        ]


if __name__ == "__main__":
    AgentFirewall.run_from_command_line()


