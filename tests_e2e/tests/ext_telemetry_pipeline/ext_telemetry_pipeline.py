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
# This test ensures that the agent does not throw any errors while trying to transmit events to wireserver. It does not
# # validate if the events actually make it to wireserver
#

# from tests_e2e.tests.agent_bvt.vm_access import VmAccessBvt
from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtTelemetryPipeline(AgentTest):
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Set the etp collection period to 30 seconds instead of default 5 minutes
        log.info("")
        log.info("Set ETP collection period to 30 seconds on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Debug.EtpCollectionPeriod=30", use_sudo=True)
        log.info("Updated waagent conf with Debug.ETPCollectionPeriod=30 completed:\n%s", output)

        # Add VmAccess to the test VM
        log.info("")
        log.info("Add VmAccess ext to the test VM and ensure vm is accessible with the new credentials...")
        # TODO VmAccessBvt.run()

        # Add CSE to the test VM
        log.info("")
        log.info("Add CSE to the test VM...")
        cse = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        cse.enable(settings={'commandToExecute': "date"})
        cse.assert_instance_view()

        # Check agent log to verify ETP is enabled
        command = f"agent_ext_workflow-check_data_in_agent_log.py --data 'Extension Telemetry pipeline enabled: True'"
        log.info("")
        log.info("Check agent log to verify ETP is enabled...".format(command))
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command))

        # TODO: Validate there is an events dir for each extension on the machine

        # TODO: Ensure good events are reported

        # TODO: Ensure bad events are reported

        # TODO: Ensure all events are deleted


if __name__ == "__main__":
    ExtTelemetryPipeline.run_from_command_line()
