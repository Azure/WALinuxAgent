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
# This test disables extension processing on waagent.conf and verifies that extensions are not processed, but the
# agent continues reporting status.
#

import datetime
import pytz

from assertpy import assert_that, fail
from typing import Any, Dict, List

from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtensionsDisabled(AgentTest):
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Disable extension processing on the test VM
        log.info("Disabling extension processing on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Extensions.Enabled=n", use_sudo=True)
        log.info("Disable completed:\n%s", output)

        disabled_timestamp: datetime.datetime = datetime.datetime.utcnow() - datetime.timedelta(minutes=60)

        #
        # Validate that the agent is not processing extensions by attempting to run CSE & checking that provisioning fails fast
        #
        log.info("Executing CustomScript; the agent should report a VMExtensionProvisioningError without processing the extension")
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        try:
            # Use mkdir in script settings so we can check if the command was executed
            custom_script.enable(settings={'commandToExecute': "mkdir /var/lib/waagent/testdir"}, force_update=True, timeout=6 * 60)
            fail("The agent should have reported an error processing the goal state")
        except Exception as error:
            assert_that("VMExtensionProvisioningError" in str(error)) \
                .described_as(f"Expected a VMExtensionProvisioningError error, but actual error was: {error}") \
                .is_true()
            assert_that("Extension will not be processed since extension processing is disabled" in str(error)) \
                .described_as(f"Error message should communicate that extension will not be processed, but actual error "
                              f"was: {error}").is_true()
            log.info("Goal state processing failed as expected")

        #
        # Validate the agent is not processing extensions by checking it did not execute the extension settings
        #
        try:
            ssh_client.run_command("dir /var/lib/waagent/testdir", use_sudo=True)
            fail("The extension settings should not have been executed")
        except CommandError as error:
            assert_that(error.stderr)\
                .described_as("Extension should not be processed, but extension settings were executed")\
                .contains('No such file or directory')
            log.info("The agent did not execute the extension settings as expected")


        #
        # Validate that the agent continued reporting status even if it is not processing extensions
        #
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        instance_view: VirtualMachineInstanceView = vm.get_instance_view()
        log.info("Instance view of VM Agent:\n%s", instance_view.vm_agent.serialize())
        assert_that(instance_view.vm_agent.statuses).described_as("The VM agent should have exactly 1 status").is_length(1)
        assert_that(instance_view.vm_agent.statuses[0].display_status).described_as("The VM Agent should be ready").is_equal_to('Ready')
        # The time in the status is time zone aware and 'disabled_timestamp' is not; we need to make the latter time zone aware before comparing them
        assert_that(instance_view.vm_agent.statuses[0].time)\
            .described_as("The VM Agent should be have reported status even after extensions were disabled")\
            .is_greater_than(pytz.utc.localize(disabled_timestamp))
        log.info("The VM Agent reported status after extensions were disabled, as expected.")

        #
        # Validate that the agent processes extensions after re-enabling extension processing
        #
        log.info("Enabling extension processing on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Extensions.Enabled=y", use_sudo=True)
        log.info("Enable completed:\n%s", output)

        try:
            custom_script.enable(settings={'commandToExecute': "date"}, force_update=True, timeout=15 * 60)
        except Exception as error:
            log.info("Goal state processing unexpectedly failed after re-enabling extension processing")


    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            {'message': 'No handler status found for Microsoft.Azure.Extensions.CustomScript'},
        ]


if __name__ == "__main__":
    ExtensionsDisabled.run_from_command_line()
