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

import random
from typing import List, Dict, Any

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtTelemetryPipeline(AgentTest):
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Extensions we will create events for
        extensions = ["Microsoft.OSTCExtensions.VMAccessForLinux", "Microsoft.Azure.Extensions.CustomScript"]
        if "-flatcar" in ssh_client.run_command("uname -a"):
            # Currently VmAccess is not supported on flatcar
            extensions = ["Microsoft.Azure.Extensions.CustomScript"]

        # Set the etp collection period to 30 seconds instead of default 5 minutes
        log.info("")
        log.info("Set ETP collection period to 30 seconds on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Debug.EtpCollectionPeriod=30", use_sudo=True)
        log.info("Updated waagent conf with Debug.ETPCollectionPeriod=30 completed:\n%s", output)

        # Add CSE to the test VM twice to ensure its events directory still exists after re-enabling
        log.info("")
        log.info("Add CSE to the test VM...")
        cse = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        cse.enable(settings={'commandToExecute': "echo 'enable'"})
        cse.assert_instance_view()

        log.info("")
        log.info("Add CSE to the test VM again...")
        cse.enable(settings={'commandToExecute': "echo 'enable again'"})
        cse.assert_instance_view()

        # Check agent log to verify ETP is enabled
        command = "agent_ext_workflow-check_data_in_agent_log.py --data 'Extension Telemetry pipeline enabled: True'"
        log.info("")
        log.info("Check agent log to verify ETP is enabled...")
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command))

        # Add good extension events for each extension and check that the TelemetryEventsCollector collects them
        log.info("")
        log.info("Add good extension events and check they are reported...")
        max_events = random.randint(10, 50)
        output = ssh_client.run_command(f"ext_telemetry_pipeline-add_extension_events.py "
                                        f"--extensions {','.join(extensions)} "
                                        f"--num_events_total {max_events}", use_sudo=True)
        log.info(output)
        log.info("")
        log.info("Good extension events were successfully reported.")

        # Add invalid events for each extension and check that the TelemetryEventsCollector drops them
        log.info("")
        log.info("Add bad extension events and check they are reported...")
        output = ssh_client.run_command(f"ext_telemetry_pipeline-add_extension_events.py "
                                        f"--extensions {','.join(extensions)} "
                                        f"--num_events_total {max_events} "
                                        f"--num_events_bad {random.randint(5, max_events-5)}", use_sudo=True)
        log.info(output)
        log.info("")
        log.info("Bad extension events were successfully dropped.")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            {'message': r"Dropped events for Extension.*"}
        ]


if __name__ == "__main__":
    ExtTelemetryPipeline.run_from_command_line()
