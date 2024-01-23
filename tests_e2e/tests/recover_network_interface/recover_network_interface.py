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

#
# This test uses CSE to bring the network down and call check_and_recover_nic_state to bring the network back into an
# 'up' and 'connected' state. The intention of the test is to alert us if there is some change in newer distros which
# affects this logic.
#

import json

from assertpy import fail, assert_that
from time import sleep

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds


class RecoverNetworkInterface(AgentVmTest):
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._context = context
        self._ssh_client = context.create_ssh_client()
        self._private_ip = context.vm.get_private_ip_address()
        self._vm_password = ""

    def add_vm_password(self):
        # Add password to VM to help with debugging in case of failure
        # REMOVE PWD FROM LOGS IF WE EVER MAKE THESE RUNS/LOGS PUBLIC
        username = self._ssh_client.username
        pwd = self._ssh_client.run_command("openssl rand -base64 32 | tr : .").rstrip()
        self._vm_password = pwd
        log.info("VM Username: {0}; VM Password: {1}".format(username, pwd))
        self._ssh_client.run_command("echo '{0}:{1}' | sudo -S chpasswd".format(username, pwd))

    def check_agent_reports_status(self):
        status_updated = False
        last_agent_status_time = self._context.vm.get_instance_view().vm_agent.statuses[0].time
        log.info("Agent reported status at {0}".format(last_agent_status_time))
        retries = 3

        while retries > 0 and not status_updated:
            agent_status_time = self._context.vm.get_instance_view().vm_agent.statuses[0].time
            if agent_status_time != last_agent_status_time:
                status_updated = True
                log.info("Agent reported status at {0}".format(last_agent_status_time))
            else:
                retries -= 1
                sleep(60)

        if not status_updated:
            fail("Agent hasn't reported status since {0} and ssh connection failed. Use the serial console in portal "
                 "to debug".format(last_agent_status_time))

    def run(self):
        # Add password to VM and log. This allows us to debug with serial console if necessary
        log.info("")
        log.info("Adding password to the VM to use for debugging in case necessary...")
        self.add_vm_password()

        # Get the primary network interface name
        ifname = self._ssh_client.run_command("pypy3 -c 'from azurelinuxagent.common.osutil.redhat import RedhatOSUtil; print(RedhatOSUtil().get_if_name())'").rstrip()
        # The interface name needs to be in double quotes for the pypy portion of the script
        formatted_ifname = f'"{ifname}"'

        # The script should bring the primary network interface down and use the agent to recover the interface. These
        # commands will bring the network down, so they should be executed on the machine using CSE instead of ssh.
        script = f"""
        ifdown {ifname};
        nic_state=$(nmcli -g general.state device show {ifname})
        echo Primary network interface state before recovering: $nic_state
        source /home/{self._context.username}/bin/set-agent-env;
        pypy3 -c 'from azurelinuxagent.common.osutil.redhat import RedhatOSUtil; RedhatOSUtil().check_and_recover_nic_state({formatted_ifname})';
        nic_state=$(nmcli -g general.state device show {ifname});
        echo Primary network interface state after recovering: $nic_state
        """
        log.info("")
        log.info("Using CSE to bring the primary network interface down and call the OSUtil to bring the interface back up. Command to execute: {0}".format(script))
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        custom_script.enable(
            protected_settings={
                'commandToExecute': script
            }
        )

        # Check that the interface was down and brought back up in instance view
        log.info("")
        log.info("Checking the instance view to confirm the primary network interface was brought down and successfully recovered by the agent...")
        instance_view = custom_script.get_instance_view()
        log.info("Instance view for custom script after enable is: {0}".format(json.dumps(instance_view.serialize(), indent=4)))
        assert_that(len(instance_view.statuses)).described_as("Instance view should have a status for CustomScript").is_greater_than(0)
        assert_that(instance_view.statuses[0].message).described_as("The primary network interface should be in a disconnected state before the attempt to recover").contains("Primary network interface state before recovering: 30 (disconnected)")
        assert_that(instance_view.statuses[0].message).described_as("The primary network interface should be in a connected state after the attempt to recover").contains("Primary network interface state after recovering: 100 (connected)")

        # Check that the agent is successfully reporting status after recovering the network
        log.info("")
        log.info("Checking that the agent is reporting status after recovering the network...")
        self.check_agent_reports_status()

        log.info("")
        log.info("The primary network interface was successfully recovered by the agent.")


if __name__ == "__main__":
    RecoverNetworkInterface.run_from_command_line()
