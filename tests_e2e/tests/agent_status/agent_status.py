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
# Validates the agent status is updated without processing additional goal states (aside from the first goal state
# from fabric)
#

from azure.mgmt.compute.models import VirtualMachineInstanceView
from assertpy import assert_that
from datetime import datetime, timedelta
from time import sleep
import json

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


class InstanceViewAgentStatusException(BaseException):
    pass


class AgentStatus(AgentTest):
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def validate_instance_view_vmagent_status(self, instance_view: VirtualMachineInstanceView):
        status = instance_view.vm_agent.statuses[0]

        # Validate message field
        message = status.message
        if message is None:
            raise InstanceViewAgentStatusException("Instance view is missing an agent status message")
        elif 'unresponsive' in message:
            raise InstanceViewAgentStatusException("Instance view shows unresponsive agent")

        # Validate display status field
        display_status = status.display_status
        if display_status is None:
            raise InstanceViewAgentStatusException("Instance view is missing an agent display status")
        elif 'Not Ready' in display_status:
            raise InstanceViewAgentStatusException("Instance view shows agent status is not ready")

        # Validate time field
        time = status.time
        if time is None:
            raise InstanceViewAgentStatusException("Instance view is missing an agent status timestamp")

    def validate_instance_view_vmagent(self, instance_view: VirtualMachineInstanceView):
        # Validate vm_agent_version field
        vm_agent_version = instance_view.vm_agent.vm_agent_version
        if vm_agent_version is None:
            raise InstanceViewAgentStatusException("Instance view is missing agent version")
        elif 'Unknown' in vm_agent_version:
            raise InstanceViewAgentStatusException("Instance view shows agent version is unknown")

        # Validate statuses field
        statuses = instance_view.vm_agent.statuses
        if statuses is None:
            raise InstanceViewAgentStatusException("Instance view is missing agent statuses")
        elif len(statuses) < 1:
            raise InstanceViewAgentStatusException("Instance view is missing an agent status entry")
        else:
            self.validate_instance_view_vmagent_status(instance_view=instance_view)

    def validate_instance_view(self, instance_view: VirtualMachineInstanceView):
        """
        Checks that instance view has vm_agent.statuses and vm_agent.vm_agent_version properties which report the Guest
        Agent as running and Ready:

        "vm_agent": {
            "extension_handlers": [],
            "vm_agent_version": "9.9.9.9",
            "statuses": [
                {
                    "level": "Info",
                    "time": "<class 'datetime.datetime'>",
                    "message": "Guest Agent is running",
                    "code": "ProvisioningState/succeeded",
                    "display_status": "Ready"
                }
            ]
        }
        """
        if instance_view.vm_agent is None:
            raise InstanceViewAgentStatusException("Instance view is missing vm agent")
        else:
            self.validate_instance_view_vmagent(instance_view=instance_view)

        if instance_view.statuses is None:
            raise InstanceViewAgentStatusException("Instance view is missing statuses")

        log.info("Instance view has valid agent status, agent version: {0}, status: {1}"
                 .format(instance_view.vm_agent.vm_agent_version, instance_view.vm_agent.statuses[0].display_status))

    def check_status_updated(self, status_timestamp: datetime, prev_status_timestamp: datetime, gs_processed_log: str, prev_gs_processed_log: str):
        # If prev_ variables are not updated, then this is the first reported agent status
        if prev_status_timestamp is not None and prev_gs_processed_log is not None:
            # The agent status timestamp should be greater than the prev timestamp
            if status_timestamp > prev_status_timestamp:
                log.info(
                    "Current agent status timestamp {0} is greater than previous status timestamp {1}"
                    .format(status_timestamp, prev_status_timestamp))
            else:
                raise Exception("Agent status failed to update: Current agent status timestamp {0} is not greater than "
                                "previous status timestamp {1}".format(status_timestamp, prev_status_timestamp))

            # The last goal state processed in the agent log should be the same as before
            if prev_gs_processed_log == gs_processed_log:
                log.info(
                    "The last processed goal state is the same as the last processed goal state in the last agent "
                    "status update: \n{0}".format(gs_processed_log)
                    .format(status_timestamp, prev_status_timestamp))
            else:
                raise Exception("Agent status failed to update without additional goal state: The agent processed an "
                                "additional goal state since the last agent status update. \n{0}"
                                "".format(gs_processed_log))

            log.info("")
            log.info("The agent status successfully updated without additional goal states")

    def run(self):
        log.info("")
        log.info("*******Verifying the agent status updates 3 times*******")

        vm = VirtualMachineClient(self._context.vm)

        timeout = datetime.now() + timedelta(minutes=5)
        instance_view_exception = None
        status_updated = 0
        prev_status_timestamp = None
        prev_gs_processed_log = None

        # Retry validating agent status updates 3 times with timeout of 5 minutes
        while datetime.now() <= timeout and status_updated < 3:
            instance_view = vm.get_instance_view()
            log.info("")
            log.info(
                "Check instance view to validate that the Guest Agent reports valid status...")
            log.info("Instance view of VM is:\n%s", json.dumps(instance_view.serialize(), indent=2))

            try:
                # Validate the guest agent reports valid status
                self.validate_instance_view(instance_view)

                status_timestamp = datetime.strptime(instance_view.vm_agent.statuses[0].time, u'%Y-%m-%dT%H:%M:%S.%fZ')
                gs_processed_log = self._ssh_client.run_command(
                    "agent_status-get_last_gs_processed.py", use_sudo=True)

                log.info("")
                log.info("Check that the agent status updated without processing any additional goal states...")
                self.check_status_updated(status_timestamp, prev_status_timestamp, gs_processed_log, prev_gs_processed_log)

                # Update variables with timestamps for this update
                status_updated += 1
                prev_status_timestamp = status_timestamp
                prev_gs_processed_log = gs_processed_log

                # Sleep 6s to allow agent status to update before we check again - agent status should be updated every 6s
                sleep(6)

            except InstanceViewAgentStatusException as e:
                instance_view_exception = str(e)
                log.info("")
                log.info("Instance view has invalid agent status: {0}".format(instance_view_exception))
                log.info("Waiting 60s before retry...")
                sleep(60)

        # If status_updated is 0, we know the agent status in the instance view was never valid
        log.info("")
        assert_that(status_updated > 0).described_as(
            "Timeout has expired, instance view has invalid agent status: {0}".format(
                instance_view_exception)).is_true()

        # Fail the test if we weren't able to validate the agent status updated 3 times
        assert_that(status_updated == 3).described_as(
            "Timeout has expired, the agent status failed to update 3 times").is_true()


if __name__ == "__main__":
    AgentStatus.run_from_command_line()
