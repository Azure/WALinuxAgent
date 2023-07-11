#!/usr/bin/env python3
import datetime
from time import sleep

from assertpy import assert_that
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

from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


def validate_instance_view_vmagent_status(instance_view: VirtualMachineInstanceView):
    is_valid = True
    status = instance_view.vm_agent.statuses[0]

    # Validate message field
    message = status.message
    if message is None:
        is_valid = False
        log.info("Instance view is missing an agent status message, waiting to retry...")
    elif 'unresponsive' in message:
        is_valid = False
        log.info("Instance view shows unresponsive agent, waiting to retry...")

    # Validate display status field
    display_status = status.display_status
    if display_status is None:
        is_valid = False
        log.info("Instance view is missing an agent display status, waiting to retry...")
    elif 'Not Ready' in display_status:
        is_valid = False
        log.info("Instance view shows agent status is not ready, waiting to retry...")

    return is_valid


def validate_instance_view_vmagent(instance_view: VirtualMachineInstanceView):
    is_valid = True

    # Validate vm_agent_version field
    vm_agent_version = instance_view.vm_agent.vm_agent_version
    if vm_agent_version is None:
        is_valid = False
        log.info("Instance view is missing agent version, waiting to retry...")
    elif 'Unknown' in vm_agent_version:
        is_valid = False
        log.info("Instance view shows agent version is unknown, waiting to retry...")

    # Validate statuses field
    statuses = instance_view.vm_agent.statuses
    if statuses is None:
        is_valid = False
        log.info("Instance view is missing agent statuses, waiting to retry...")
    elif len(statuses) < 1:
        is_valid = False
        log.info("Instance view is missing an agent status entry, waiting to retry...")
    else:
        is_valid = validate_instance_view_vmagent_status(instance_view=instance_view)

    return is_valid


def validate_instance_view(instance_view: VirtualMachineInstanceView):
    instance_view_is_valid = True

    if instance_view.vm_agent is None:
        instance_view_is_valid = False
        log.info("Instance view is missing vm agent, waiting to retry...")
    else:
        instance_view_is_valid = validate_instance_view_vmagent(instance_view=instance_view)

    if instance_view.statuses is None:
        instance_view_is_valid = False
        log.info("Instance view is missing statuses, waiting to retry...")

    if instance_view_is_valid:
        log.info("Instance view is valid, agent version: {0}, status: {1}"
                 .format(instance_view.vm_agent.vm_agent_version,
                         instance_view.vm_agent.statuses[0].display_status))

    return instance_view_is_valid


class AgentStatus(AgentTest):
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

    def run(self):
        log.info("")
        log.info("*******Verifying the agent status*******")

        vm = VirtualMachineClient(self._context.vm)

        timeout = datetime.datetime.now() + datetime.timedelta(minutes=5)
        instance_view_is_valid = False

        while datetime.datetime.now() < timeout and not instance_view_is_valid:
            instance_view = vm.get_instance_view()
            log.info("")
            log.info("Validating VM Instance View...")
            log.info("Instance view of VM is:\n%s", instance_view.serialize())

            instance_view_is_valid = validate_instance_view(instance_view)
            if not instance_view_is_valid:
                log.info("")
                log.info("Instance view is not valid, waiting 10s before retry...")
                sleep(10)

        log.info("")
        assert_that(instance_view_is_valid).described_as("Timeout has expired, instance view is not valid.").is_true()


if __name__ == "__main__":
    AgentStatus.run_from_command_line()
