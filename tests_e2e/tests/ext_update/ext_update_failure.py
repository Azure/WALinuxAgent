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
from typing import List, Dict, Any

from assertpy import fail, assert_that

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier


class ExtensionUpdateFailureTest(AgentVmTest):
    """
    This test verifies that the agent reports correct status and code when extension operation fails during the ext update.
    """

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()
        is_arm64: bool = ssh_client.get_architecture() == "aarch64"

        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript,
            resource_name="CustomScript")

        if is_arm64:
            log.info("Will skip the update scenario, since currently there is only 1 version of CSE on ARM64")
            return
        else:
            log.info("Installing %s", custom_script_2_0)
            message = f"Hello {uuid.uuid4()}!"
            custom_script_2_0.enable(
                protected_settings={
                    'commandToExecute': f"echo \'{message}\'"
                },
                auto_upgrade_minor_version=False
            )
            custom_script_2_0.assert_instance_view(expected_version="2.0", expected_message=message)

        log.info("Modifying existing handler commands (disable operation) in HandlerManifest.json to fail the disable operation during update")

        output = ssh_client.run_command(f"ext_update-modify_handler_manifest.py --extension-name '{custom_script_2_0._identifier}' --cmd-name disableCommand --cmd-value 'disablefailed'", use_sudo=True)
        log.info("Modified handlerManifest.json:\n%s", output)

        custom_script_2_1 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"),
            resource_name="CustomScript")

        log.info("Updating %s", custom_script_2_0)

        message = f"Hello {uuid.uuid4()}!"
        try:
            custom_script_2_1.enable(
                protected_settings={
                    'commandToExecute': f"echo \'{message}\'"
                }
            )
            fail("The agent should have reported an error processing the extension update")
        except Exception as error:
            assert_that(str(error)).described_as(f"Expected VMExtensionHandlerNonTransientError/ExtensionUpdateError for {custom_script_2_1._identifier}, but actual error was: {error}").contains("VMExtensionHandlerNonTransientError").contains(f"{custom_script_2_1._identifier}").contains("ExtensionUpdateError")
            log.info("Goal state processing for %s failed as expected", custom_script_2_1._identifier)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # 		2025-07-09T18:06:42.560709Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Extensions.CustomScript, op=Disable, message=[ExtensionOperationError] Non-zero exit code: 2, /var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.0.7/bin/custom-script-shim disablefailed
            # 		[stdout]
            # 		+ /var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.0.7/bin/custom-script-extension disablefailed
            # 		Usage: /var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.0.7/bin/custom-script-extension disable|install|uninstall|enable|update
            # 		v2.0.7 git:1f9c51c-clean build:2019-06-17T20:53:51Z go1.10.4
            # 		Incorrect command: "disablefailed"
            #
            #
            # 		[stderr]
            # 		Running scope as unit: disable_3dc6fbcb-df81-49a4-8251-3a47d9ea686e.scope
            # 		; ContinueOnUpdate: False, duration=0
            {
                'message': r"name=Microsoft.Azure.Extensions.CustomScript, op=Disable, message=\[ExtensionOperationError\] .*disablefailed"
            }
        ]
        return ignore_rules

if __name__ == "__main__":
    ExtensionUpdateFailureTest.run_from_command_line()
