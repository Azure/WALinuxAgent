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
from pathlib import Path

from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class InstallExtensions:
    """
    This test installs the multiple extensions in order to verify extensions cgroups in the next test.
    """

    def __init__(self, context: AgentVmTestContext):
        self._context = context
        self._ssh_client = self._context.create_ssh_client()

    def run(self) -> None:
        """
        Installs the extensions used to validate cgroups
        """

        # Install the GATest extension to test service cgroups
        self._install_gatest_extension()

        # Install the VM Access extension to test sample extension
        self._install_vmaccess()

        # Install the CSE extension to test extension cgroup.
        self._install_cse()

    def _install_vmaccess(self):
        # fetch the public key
        public_key_file: Path = Path(self._context.identity_file).with_suffix(".pub")
        with public_key_file.open() as f:
            public_key = f.read()
        # Invoke the extension
        vm_access = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.VmAccess)
        log.info("Installing %s", vm_access)
        vm_access.enable(
            protected_settings={
                'username': self._context.username,
                'ssh_key': public_key,
                'reset_ssh': 'false'
            }
        )
        vm_access.assert_instance_view()

    def _install_gatest_extension(self):
        gatest_extension = VirtualMachineExtensionClient(
            self._context.vm, VmExtensionIds.GATestExtension)
        log.info("Installing %s", gatest_extension)
        gatest_extension.enable()
        gatest_extension.assert_instance_view()

    def _install_cse(self):
        # Custom script that:
        #   1. Saves the cgroup info of the CSE process itself (for CSE cgroup validation).
        #   2. Spawns a long-running dummy process (`sleep`) that survives after CSE exits.
        #   3. Writes the dummy process PID to /var/lib/waagent/tmp/dummy_proc.pid.
        # CSE exits quickly with success.
        command = (
            "mkdir -p /var/lib/waagent/tmp; "
            "cp /proc/$$/cgroup /var/lib/waagent/tmp/custom_script_check; "
            "nohup sh -c "
            "'echo $$ > /var/lib/waagent/tmp/dummy_proc.pid; exec sleep 100000' "
            "</dev/null >/dev/null 2>&1 &"
        )
        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)

        log.info("Installing %s", custom_script_2_0)
        custom_script_2_0.enable(
            settings={},
            protected_settings={
                'commandToExecute': command
            }
        )
        custom_script_2_0.assert_instance_view()

