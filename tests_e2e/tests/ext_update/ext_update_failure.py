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
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier


class ExtensionUpdateFailureTest(AgentVmTest):
    """
    This test verifies that the agent reports correct status and code when extension operation fails during the ext update.
    """
    def __init__(self, context):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        custom_script = VmExtensionIds.CustomScript
        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            custom_script)
        extensions_to_cleanup = {
            custom_script: custom_script_2_0
        }
        try:
            log.info("Removing existing extensions: %s", extensions_to_cleanup.keys())
            self._remove_extensions(extensions_to_cleanup)

            log.info("Installing %s", custom_script_2_0)
            message = f"Hello {uuid.uuid4()}!"
            custom_script_2_0.enable(
                settings={},
                protected_settings={
                    'commandToExecute': f"echo \'{message}\'"
                },
                auto_upgrade_minor_version=False
            )
            custom_script_2_0.assert_instance_view(expected_version="2.0", expected_message=message)

            log.info("Modifying existing handler commands (disable operation) in HandlerManifest.json to fail the disable operation during update")

            output = self._ssh_client.run_command(f"ext_update-modify_handler_manifest.py --extension-name {custom_script} --properties disableCommand=disablefailed continueOnUpdateFailure=false", use_sudo=True)
            log.info("Modified handlerManifest.json:\n%s", output)

            custom_script_2_1 = VirtualMachineExtensionClient(
                self._context.vm,
                VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"))

            log.info("Updating %s", custom_script_2_0)

            message = f"Hello {uuid.uuid4()}!"
            try:
                custom_script_2_1.enable(
                    settings={},
                    protected_settings={
                        'commandToExecute': f"echo \'{message}\'"
                    }
                )
                fail("The agent should have reported an error processing the extension update")
            except Exception as error:
                assert_that(str(error)).described_as(f"Expected VMExtensionHandlerNonTransientError/ExtensionUpdateError for {custom_script}, but actual error was: {error}").contains("VMExtensionHandlerNonTransientError").contains(f"{custom_script}").contains("ExtensionUpdateError")
                log.info("Goal state processing for %s failed as expected", custom_script)

        finally:
            log.info("Cleaning up extensions")
            self._remove_extensions(extensions_to_cleanup)

    def _remove_extensions(self, extensions_to_cleanup):
        extensions_on_vm = self._context.vm.get_extensions().value
        extension_names_on_vm = {ext.name for ext in extensions_on_vm}
        log.info("Extensions currently on VM: %s", extension_names_on_vm)

        for ext_name, ext in extensions_to_cleanup.items():
            if ext._resource_name in extension_names_on_vm:
                self._ssh_client.run_command(f"ext_update-modify_handler_manifest.py --extension-name {ext_name} --reset", use_sudo=True)
                ext.delete()
                log.info("Removed extension %s", ext_name)

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
            },

            # In some distros, scope not included in the error, so we consider as systemd error
            # 2025-07-21T22:07:23.541880Z INFO ExtHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Failed to start Microsoft.Azure.Extensions.CustomScript-2.0.7 using systemd-run, will try invoking the extension directly. Error: [SystemdRunError] Systemd process exited with code 1 and output [stdout]
            # [stderr]
            # Failed to find executable /var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.0.7/disablefailed: No such file or directory
            {
                'message': r"Failed to start Microsoft.Azure.Extensions.CustomScript.* using systemd-run, will try invoking the extension directly"
            }
        ]
        return ignore_rules

if __name__ == "__main__":
    ExtensionUpdateFailureTest.run_from_command_line()
