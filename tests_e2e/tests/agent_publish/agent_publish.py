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
import uuid
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class AgentPublishTest(AgentTest):
    """
    This script verifies if the agent update performed in the vm.
    """

    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def run(self):
        """
        we run the scenario in the following steps:
            1. Print the current agent version before the update
            2. Prepare the agent for the update
            3. Check for agent update from the log
            4. Print the agent version after the update
            5. Ensure CSE is working
        """
        self._get_agent_info()
        self._prepare_agent()
        self._check_update()
        self._get_agent_info()
        self._check_cse()

    def _get_agent_info(self) -> None:
        stdout: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info('Agent info \n%s', stdout)

    def _prepare_agent(self) -> None:
        log.info("Modifying agent update related config flags")
        self._run_remote_test("update-waagent-conf Debug.DownloadNewAgents=y AutoUpdate.GAFamily=Test", use_sudo=True)
        log.info('Updated agent-update DownloadNewAgents  GAFamily config flags')

    def _check_update(self) -> None:
        log.info("Verifying for agent update status")
        self._run_remote_test("agent_publish-check_update.py")
        log.info('Successfully checked the agent update')

    def _check_cse(self) -> None:
        custom_script_2_1 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"),
            resource_name="CustomScript")

        log.info("Installing %s", custom_script_2_1)
        message = f"Hello {uuid.uuid4()}!"
        custom_script_2_1.enable(
            settings={
                'commandToExecute': f"echo \'{message}\'"
            },
            auto_upgrade_minor_version=False
        )
        custom_script_2_1.assert_instance_view(expected_version="2.1", expected_message=message)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # This is expected as latest version can be the less than test version
            #
            # WARNING ExtHandler ExtHandler Agent WALinuxAgent-9.9.9.9 is permanently blacklisted
            #
            {
                'message': r"Agent WALinuxAgent-9.9.9.9 is permanently blacklisted"
            }

        ]
        return ignore_rules


if __name__ == "__main__":
    AgentPublishTest.run_from_command_line()
