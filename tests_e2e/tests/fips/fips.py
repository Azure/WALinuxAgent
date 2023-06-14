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
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.identifiers import VmExtensionIds


class Fips(AgentTest):
    """
    Enables FIPS on the test VM, which is a RHEL 9 VM (see https://access.redhat.com/solutions/137833#rhel9), then executes the CustomScript extension.

    TODO: Investigate whether extensions with protected settings are supported on FIPS-enabled systems. The Agent has issues handling the tenant
          certificate on those systems (additional configuration on FIPS may be needed).
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        try:
            command = "fips-mode-setup --enable"
            log.info("Enabling FIPS on the test VM [%s]", command)
            output = ssh_client.run_command(command, use_sudo=True)
            log.info("Enable FIPS completed\n%s", output)
        except CommandError as e:
            raise Exception(f"Failed to enable FIPS: {e}")

        log.info("Restarting test VM")
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        vm.restart(wait_for_boot=True, ssh_client=ssh_client)

        try:
            command = "fips-mode-setup --check"
            log.info("Verifying that FIPS is enabled [%s]", command)
            output = ssh_client.run_command(command).rstrip()
            if output != "FIPS mode is enabled.":
                fail(f"FIPS i not enabled - '{command}' returned '{output}'")
            log.info(output)
        except CommandError as e:
            raise Exception(f"Failed to verify that FIPS is enabled: {e}")

        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")

        log.info("Installing %s", custom_script)
        message = f"Hello {uuid.uuid4()}!"
        custom_script.enable(
            settings={
                'commandToExecute': f"echo \'{message}\'"
            },
            auto_upgrade_minor_version=False
        )
        custom_script.assert_instance_view(expected_version="2.0", expected_message=message)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        """
        Some extensions added by policy on the test subscription use protected settings, which produce this error.
        """
        return [
            {'message': r'Failed to decrypt /var/lib/waagent/Certificates.p7m'}
        ]


if __name__ == "__main__":
    Fips.run_from_command_line()

