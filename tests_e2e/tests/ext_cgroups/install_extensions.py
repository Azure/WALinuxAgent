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
from datetime import datetime, timedelta
from pathlib import Path

from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class InstallExtensions:
    """
    This test installs the multiple extensions in order to verify extensions cgroups in the next test.
    """

    def __init__(self, context: AgentTestContext):
        self._context = context
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        self._prepare_agent()
        # Install the GATest extension to test service cgroups
        self._install_gatest_extension()
        # Install the Azure Monitor Agent to test long running process cgroup
        self._install_ama()
        # Install the VM Access extension to test sample extension
        self._install_vmaccess()
        # Install the CSE extension to test extension cgroup
        self._install_cse()

    def _prepare_agent(self):
        log.info("=====Executing update-waagent-conf remote script to update monitoring deadline flag for tracking azuremonitoragent service")
        future_date = datetime.utcnow() + timedelta(days=2)
        expiry_time = future_date.date().strftime("%Y-%m-%d")
        # Agent needs extension info and it's services info in the handlermanifest.xml to monitor and limit the resource usage.
        # As part of pilot testing , agent hardcoded azuremonitoragent service name to monitor it for sometime in production without need of manifest update from extesnion side.
        # So that they can get sense of resource usage for their extensions. This we did for few months and now we no logner monitoring it in production.
        # But we are changing the config flag expiry time to future date in this test. So that test agent will start track the cgroups that is used by the service.
        result = self._ssh_client.run_command(f"update-waagent-conf Debug.CgroupMonitorExpiryTime={expiry_time}", use_sudo=True)
        log.info(result)
        log.info("Updated agent cgroups config(CgroupMonitorExpiryTime)")

    def _install_ama(self):
        ama_extension = VirtualMachineExtensionClient(
            self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent,
            resource_name="AMAAgent")
        log.info("Installing %s", ama_extension)
        ama_extension.enable()
        ama_extension.assert_instance_view()

    def _install_vmaccess(self):
        # fetch the public key
        public_key_file: Path = Path(self._context.private_key_file).with_suffix(".pub")
        with public_key_file.open() as f:
            public_key = f.read()
        # Invoke the extension
        vm_access = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.VmAccess, resource_name="VmAccess")
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
            self._context.vm, VmExtensionIds.GATestExtension,
            resource_name="GATestExt")
        log.info("Installing %s", gatest_extension)
        gatest_extension.enable()
        gatest_extension.assert_instance_view()


    def _install_cse(self):
        # Use custom script to output the cgroups assigned to it at runtime and save to /var/lib/waagent/tmp/custom_script_check.
        script_contents = """
mkdir /var/lib/waagent/tmp
cp /proc/$$/cgroup /var/lib/waagent/tmp/custom_script_check
"""
        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript,
            resource_name="CustomScript")

        log.info("Installing %s", custom_script_2_0)
        custom_script_2_0.enable(
            protected_settings={
                'commandToExecute': f"echo \'{script_contents}\' | bash"
            }
        )
        custom_script_2_0.assert_instance_view()

