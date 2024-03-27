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

from typing import List, Dict, Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds


class AgentCgroupsProcessCheck(AgentVmTest):
    """
    Tests the agent's ability to detect processes that do not belong to the agent's cgroup
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        """
        Steps:
        1. Verify that agent detects processes that do not belong to the agent's cgroup and disable the cgroups
        2. Run the extension, so that they are run in the agent's cgroup
        3. Restart the ext_handler process to re-initialize the cgroups setup
        4. Verify that agent detects extension processes and will not enable the cgroups
        """

        log.info("=====Validating agent cgroups process check")
        self._run_remote_test(self._ssh_client, "agent_cgroups_process_check-unknown_process_check.py", use_sudo=True)

        self._install_ama_extension()

        log.info("=====Validating agent cgroups not enabled")
        self._run_remote_test(self._ssh_client, "agent_cgroups_process_check-cgroups_not_enabled.py", use_sudo=True)

    def _install_ama_extension(self):
        ama_extension = VirtualMachineExtensionClient(
            self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent,
            resource_name="AMAAgent")
        log.info("Installing %s", ama_extension)
        ama_extension.enable()
        ama_extension.assert_instance_view()

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:

        ignore_rules = [
            # This is produced by the test, so it is expected
            # Examples:
            # 2024-04-01T19:16:11.929000Z INFO MonitorHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Check on cgroups failed:
            # [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 2957] dd\x00if=/dev/zero\x00of=/dev/null\x00                                   ']
            # 2024-04-01T19:17:04.995276Z WARNING ExtHandler ExtHandler [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 3285] /usr/bin/python3\x00/var/lib/waagent/Microsoft.Azure.Monitor.AzureM', '[PID: 3286] /usr/bin/python3\x00/var/lib/waagent/Microsoft.Azure.Monitor.AzureM']
            {'message': r"The agent's cgroup includes unexpected processes"},
            {'message': r"Found unexpected processes in the agent cgroup before agent enable cgroups"}
        ]
        return ignore_rules


if __name__ == "__main__":
    AgentCgroupsProcessCheck.run_from_command_line()
