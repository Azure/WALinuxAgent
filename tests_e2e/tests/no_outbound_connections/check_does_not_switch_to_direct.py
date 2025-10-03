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

from assertpy import fail

from azurelinuxagent.common.future import ustr
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier


class CheckDoesNotSwitchToDirect(AgentVmTest):
    """
    Verifies that the agent does not hit any errors downloading artifacts on vm with no outbound connectivity when
    primary download channel is HGAP. Asserts that the agent does not fallback to the direct download channel.
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Delete CSE if it is already installed so that we can assert it is successfully downloaded via HGAP on VM with
        # no outbound connections.
        extensions_on_vm = self._context.vm.get_extensions().value
        for ext in extensions_on_vm:
            if ext.type_properties_type == VmExtensionIds.CustomScript.type:
                log.info("Removing CSE...")
                VirtualMachineExtensionClient(self._context.vm,
                                              VmExtensionIdentifier(publisher=ext.publisher,
                                                                    ext_type=ext.type_properties_type,
                                                                    version=ext.type_handler_version)).delete()
                log.info("Deleted CSE.")

        # Attempt to install CSE. This should succeed.
        log.info("")
        log.info("Enable CSE...")
        custom_script = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)
        custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"})
        log.info("Enabled CSE successfully.")

        # Check the agent log to verify that there is no log indicating that the agent switched to the direct
        # channel for artifact downloads.
        try:
            log.info("")
            log.info("Checking agent log to verify that agent did not switch to Direct download channel...")
            unexpected_message = 'Default channel changed to Direct channel.'
            command = f"check_data_in_agent_log.py --data '{unexpected_message}'"
            log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
            # We expect check_data_in_agent_log.py to fail because it should not find the expected data. If the script
            # did not fail, fail the test.
            fail("Found agent log indicating that the agent switched to the Direct channel.")
        except CommandError as e:
            # We expect check_data_in_agent_log.py to fail because it did not find the expected data. If it failed for
            # any other reason, the test should fail.
            if 'Did not find data' not in ustr(e):
                fail(f"Caught unexpected exception while checking agent log:\n{e}")
            log.info("Did not find agent log indicating that the agent switched to the Direct channel (as expected).")


if __name__ == "__main__":
    CheckDoesNotSwitchToDirect.run_from_command_line()
