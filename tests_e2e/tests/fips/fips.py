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

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.identifiers import VmExtensionIds


class Fips(AgentVmTest):
    """
    Enables FIPS on the test VM, which is Mariner 2 VM, and verifies that extensions with protected settings are handled correctly under FIPS.
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        try:
            command = "fips-enable_fips_mariner"
            log.info("Enabling FIPS on the test VM [%s]", command)
            output = ssh_client.run_command(command)
            log.info("Enable FIPS completed\n%s", output)
        except CommandError as e:
            raise Exception(f"Failed to enable FIPS: {e}")

        log.info("Restarting test VM")
        vm: VirtualMachineClient = VirtualMachineClient(
            cloud=self._context.vm.cloud,
            location=self._context.vm.location,
            subscription=self._context.vm.subscription,
            resource_group=self._context.vm.resource_group,
            name=self._context.vm.name)
        vm.restart(wait_for_boot=True, ssh_client=ssh_client)

        try:
            command = "fips-check_fips_mariner"
            log.info("Verifying that FIPS is enabled [%s]", command)
            output = ssh_client.run_command(command).rstrip()
            if output != "FIPS mode is enabled.":
                fail(f"FIPS is not enabled - '{command}' returned '{output}'")
            log.info(output)
        except CommandError as e:
            raise Exception(f"Failed to verify that FIPS is enabled: {e}")

        # Execute an extension with protected settings to ensure the tenant certificate can be decrypted under FIPS
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        log.info("Installing %s", custom_script)
        message = f"Hello {uuid.uuid4()}!"
        custom_script.enable(
            protected_settings={
                'commandToExecute': f"echo \'{message}\'"
            }
        )
        custom_script.assert_instance_view(expected_message=message)


if __name__ == "__main__":
    Fips.run_from_command_line()

