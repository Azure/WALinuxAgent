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
from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log


class AgentFirewall(AgentTest):
    """
    This test verifies the agent firewall rules are added properly. It checks each firewall rule is present and working as expected.
    """

    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("Checking iptable rules added by the agent")
        self._run_remote_test(f"agent_firewall-verify_all_firewall_rules.py --user {self._context.username}", use_sudo=True)
        log.info("Successfully verified all rules present and working as expected.")


if __name__ == "__main__":
    AgentFirewall.run_from_command_line()


