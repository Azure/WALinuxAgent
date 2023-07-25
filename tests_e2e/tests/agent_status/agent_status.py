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
# Validates the agent status is updated without any other goal state changes
#

import datetime
import json

from azure.mgmt.compute.models import VirtualMachineInstanceView
from assertpy import assert_that
from time import sleep

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


class AgentStatus(AgentTest):
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def validate_instance_view_vmagent_status(self, instance_view: VirtualMachineInstanceView):
        status = instance_view.vm_agent.statuses[0]

        # Validate message field
        message = status.message
        if message is None:
            raise Exception("Instance view is missing an agent status message")
        elif 'unresponsive' in message:
            raise Exception("Instance view shows unresponsive agent")

        # Validate display status field
        display_status = status.display_status
        if display_status is None:
            raise Exception("Instance view is missing an agent display status")
        elif 'Not Ready' in display_status:
            raise Exception("Instance view shows agent status is not ready")

    def validate_instance_view_vmagent(self, instance_view: VirtualMachineInstanceView):
        # Validate vm_agent_version field
        vm_agent_version = instance_view.vm_agent.vm_agent_version
        if vm_agent_version is None:
            raise Exception("Instance view is missing agent version")
        elif 'Unknown' in vm_agent_version:
            raise Exception("Instance view shows agent version is unknown")

        # Validate statuses field
        statuses = instance_view.vm_agent.statuses
        if statuses is None:
            raise Exception("Instance view is missing agent statuses")
        elif len(statuses) < 1:
            raise Exception("Instance view is missing an agent status entry")
        else:
            self.validate_instance_view_vmagent_status(instance_view=instance_view)

    def validate_instance_view(self, instance_view: VirtualMachineInstanceView):
        """
        Checks that instance view has vm_agent.statuses property which reports the Guest Agent as running and Ready:

        "vm_agent": {
            "extension_handlers": [],
            "vm_agent_version": "9.9.9.9",
            "additional_properties": {},
            "statuses": [
                {
                    "level": "Info",
                    "time": "<class 'datetime.datetime'>",
                    "message": "Guest Agent is running",
                    "code": "ProvisioningState/succeeded",
                    "additional_properties": {},
                    "display_status": "Ready"
                }
            ]
        }
        """
        if instance_view.vm_agent is None:
            raise Exception("Instance view is missing vm agent")
        else:
            self.validate_instance_view_vmagent(instance_view=instance_view)

        if instance_view.statuses is None:
            raise Exception("Instance view is missing statuses")

        log.info("Instance view is valid, agent version: {0}, status: {1}"
                 .format(instance_view.vm_agent.vm_agent_version, instance_view.vm_agent.statuses[0].display_status))

    def run(self):
        log.info("")
        log.info("*******Verifying the agent status*******")

        vm = VirtualMachineClient(self._context.vm)

        timeout = datetime.datetime.now() + datetime.timedelta(minutes=5)
        instance_view_is_valid = False
        instance_view_exception = None

        # Retry validating instance view with timeout of 5 minutes
        while datetime.datetime.now() <= timeout and not instance_view_is_valid:
            instance_view = vm.get_instance_view()
            log.info("")
            log.info(
                "Check instance view to validate that the Guest Agent reports status without any new goal states...")
            log.info("Instance view of VM is:\n%s", json.dumps(instance_view.serialize(), indent=2))

            try:
                self.validate_instance_view(instance_view)
                instance_view_is_valid = True
            except Exception as e:
                instance_view_exception = str(e)
                log.info("")
                log.info("Instance view has invalid agent status: {0}".format(instance_view_exception))
                log.info("Waiting 60s before retry...")
                sleep(60)

        log.info("")
        assert_that(instance_view_is_valid).described_as(
            "Timeout has expired, instance view has invalid agent status: {0}".format(
                instance_view_exception)).is_true()


if __name__ == "__main__":
    AgentStatus.run_from_command_line()
