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
from assertpy import fail, assert_that
from typing import Any, Dict, List

from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class AgentNotProvisioned(AgentTest):
    """
    When osProfile.linuxConfiguration.provisionVMAgent is set to 'false', this test verifies that
    the agent is disabled and that extension operations are not allowed.
    """
    def run(self):
        #
        # Check the agent's log for the messages that indicate it is disabled.
        #
        ssh_client: SshClient = self._context.create_ssh_client()

        log.info("Checking the Agent's log to verify that it is disabled.")
        try:
            output = ssh_client.run_command("""
                # We need to wait for the agent to start and hit the disable code, give it a few minutes
                n=18
                for i in $(seq $n); do
                    grep -E 'WARNING.*Daemon.*Disabling guest agent in accordance with ovf-env.xml' /var/log/waagent.log || \
                    grep -E 'WARNING.*Daemon.*Disabling the guest agent by sleeping forever; to re-enable, remove /var/lib/waagent/disable_agent and restart' /var/log/waagent.log
                    if [[ $? == 0 ]]; then
                        exit 0
                    fi
                    echo "Did not find the expected message in the agent's log, retrying after sleeping for a few seconds (attempt $i/$n)..."
                    sleep 10
                done
                echo "Did not find the expected message in the agent's log, giving up."
                exit 1
            """)
            log.info("The Agent is disabled, log message: [%s]", output.rstrip())
        except CommandError as e:
            fail(f"The agent's log does not contain the expected messages: {e}")

        #
        # Validate that the agent is not reporting status.
        #
        log.info("Verifying that the Agent status is 'Not Ready' (i.e. it is not reporting status).")
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        instance_view: VirtualMachineInstanceView = vm.get_instance_view()
        log.info("Instance view of VM Agent:\n%s", instance_view.vm_agent.serialize())
        assert_that(instance_view.vm_agent.statuses).described_as("The VM agent should have exactly 1 status").is_length(1)
        assert_that(instance_view.vm_agent.statuses[0].code).described_as("The VM Agent should not be available").is_equal_to('ProvisioningState/Unavailable')
        assert_that(instance_view.vm_agent.statuses[0].display_status).described_as("The VM Agent should not ready").is_equal_to('Not Ready')
        log.info("The Agent status is 'Not Ready'")

        #
        # Validate that extensions cannot be executed.
        #
        log.info("Verifying that extension processing is disabled.")
        log.info("Executing CustomScript; it should fail.")
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        try:
            custom_script.enable(settings={'commandToExecute': "date"}, force_update=True, timeout=20 * 60)
            fail("CustomScript should have failed")
        except Exception as error:
            assert_that("OperationNotAllowed" in str(error)) \
                .described_as(f"Expected an OperationNotAllowed: {error}") \
                .is_true()
            log.info("CustomScript failed, as expected: %s", error)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            {'message': 'Disabling guest agent in accordance with ovf-env.xml'},
            {'message': 'Disabling the guest agent by sleeping forever; to re-enable, remove /var/lib/waagent/disable_agent and restart'}
        ]


if __name__ == "__main__":
    AgentNotProvisioned.run_from_command_line()

