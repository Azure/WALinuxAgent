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

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class InstallExtensions(AgentTest):
    """
    This test installs the multiple extensions in order to verify extensions cgroups in the next test.
    """

    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

    def run(self):
        self._prepare_agent()
        # Install the GATest extension
        self._install_gatest_extension()
        # Install the Azure Monitor Agent
        self._install_ama()
        # Install the VM Access extension
        self._install_vmaccess()
        # Install the CSE extension
        self._install_cse()

    def _prepare_agent(self):
        log.info("=====Updating monitoring deadline for tracking azuremonitoragent service=====")
        future_date = datetime.utcnow() + timedelta(days=2)
        expiry_time = future_date.date().strftime("%Y-%m-%d")
        # Agent needs extension info and it's services info in the handlermanifest.xml to monitor and limit the resource usage.
        # As part of pilot testing , agent hardcoded azuremonitoragent service name to monitor it for sometime in production without need of manifest update from extesnion side.
        # So that they can get sense of resource usage for their extensions. This we did for few months and now we no logner monitoring it in production.
        # But I'm mocking the same behaviour here in test by changing the expiry time to future date. So that test agent will start track the cgroups that is used by the service.
        result = self._ssh_client.run_command(f"update-waagent-conf Debug.CgroupMonitorExpiryTime={expiry_time}", use_sudo=True)
        log.info(result)
        log.info("=====Updated agent cgroups config(CgroupMonitorExpiryTime)=====")

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
        # Output the status of the agent when both CSE and AMA are running to make sure none of them were assigned
        # to the agent by mistake; save to /var/lib/waagent/tmp/walinuxagent_check_after_ama.
        script_contents = """#!/usr/bin/env bash
function check_ama {
    while true;
    do
        ama_dir=$(find /var/lib/waagent -maxdepth 1 -type d -name "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-*" -print -quit)
        grep -i "Enable succeeded" $ama_dir/status/0.status &> /dev/null
        if [ $? -eq 0 ];
        then
            ps aux --forest > /var/lib/waagent/tmp/ps_check_after_ama
            break
        fi
    done
}

mkdir /var/lib/waagent/tmp
cp /proc/$$/cgroup /var/lib/waagent/tmp/custom_script_check
check_ama &
"""

        base64script: str = self._ssh_client.run_command("echo '{0}' | base64 -w0".format(script_contents))

        settings = {"script": base64script}
        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript,
            resource_name="CustomScript")

        log.info("Installing %s", custom_script_2_0)
        custom_script_2_0.enable(
            settings=settings
        )
        custom_script_2_0.assert_instance_view()


if __name__ == "__main__":
    InstallExtensions.run_from_command_line()
