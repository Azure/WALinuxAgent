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
            raise Exception("Instance view is missing an agent status message, waiting to retry...")
        elif 'unresponsive' in message:
            raise Exception("Instance view shows unresponsive agent, waiting to retry...")

        # Validate display status field
        display_status = status.display_status
        if display_status is None:
            raise Exception("Instance view is missing an agent display status, waiting to retry...")
        elif 'Not Ready' in display_status:
            raise Exception("Instance view shows agent status is not ready, waiting to retry...")

    def validate_instance_view_vmagent(self, instance_view: VirtualMachineInstanceView):
        # Validate vm_agent_version field
        vm_agent_version = instance_view.vm_agent.vm_agent_version
        if vm_agent_version is None:
            raise Exception("Instance view is missing agent version, waiting to retry...")
        elif 'Unknown' in vm_agent_version:
            raise Exception("Instance view shows agent version is unknown, waiting to retry...")

        # Validate statuses field
        statuses = instance_view.vm_agent.statuses
        if statuses is None:
            raise Exception("Instance view is missing agent statuses, waiting to retry...")
        elif len(statuses) < 1:
            raise Exception("Instance view is missing an agent status entry, waiting to retry...")
        else:
            self.validate_instance_view_vmagent_status(instance_view=instance_view)

    def validate_instance_view(self, instance_view: VirtualMachineInstanceView):
        if instance_view.vm_agent is None:
            raise Exception("Instance view is missing vm agent, waiting to retry...")
        else:
            self.validate_instance_view_vmagent(instance_view=instance_view)

        if instance_view.statuses is None:
            raise Exception("Instance view is missing statuses, waiting to retry...")

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
            log.info("Validating VM Instance View...")
            log.info("Instance view of VM is:\n%s", json.dumps(instance_view.serialize(), indent=2))

            try:
                self.validate_instance_view(instance_view)
                instance_view_is_valid = True
            except Exception as e:
                instance_view_exception = str(e)
                log.info("")
                log.info("Instance view is not valid, waiting 60s before retry...")
                sleep(60)

        log.info("")
        assert_that(instance_view_is_valid).described_as(
            "Timeout has expired, instance view is not valid: {0}".format(instance_view_exception)).is_true()


if __name__ == "__main__":
    AgentStatus.run_from_command_line()
