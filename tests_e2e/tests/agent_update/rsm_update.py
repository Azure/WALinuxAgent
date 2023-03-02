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
# BVT for the agent update scenario
#
# The test verifies agent update for rsm workflow. This test covers three scenarios downgrade, upgrade and no update.
# For each scenario, we intiaite the rsm request with target version and then verify agent updated to that target version.
#
import json

import requests
from assertpy import assert_that
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute.models import VirtualMachine

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_not_found
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine import VmMachine


class RsmUpdateBvt(AgentTest):

    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

    def run(self) -> None:
        # Allow agent to send supported feature flag
        self._verify_agent_reported_supported_feature_flag()

        log.info("*******Verifying the Agent Downgrade scenario*******")
        self._mock_rsm_update("1.3.0.0")
        self._prepare_agent()

        # Verify downgrade scenario
        self._verify_guest_agent_update("1.3.0.0")

        # Verify upgrade scenario
        log.info("*******Verifying the Agent Upgrade scenario*******")
        self._mock_rsm_update("1.3.1.0")
        self._verify_guest_agent_update("1.3.1.0")

        # verify no version update. There is bug in CRP and will enable once it's fixed
        # log.info("*******Verifying the no version update scenario*******")
        # self._prepare_rsm_update("1.3.1.0")
        # self._verify_guest_agent_update("1.3.1.0")

    def _prepare_agent(self) -> None:
        """
        This method is to ensure agent is ready for accepting rsm updates. As part of that we update following flags
        1) Changing daemon version since daemon has a hard check on agent version in order to update agent. It doesn't allow versions which are less than daemon version.
        2) Updating GAFamily type "Test" and GAUpdates flag to process agent updates on test versions.
        """
        local_path = self._context.test_source_directory/"tests"/"scripts"/"agent-python"
        remote_path = self._context.remote_working_directory/"agent-python"
        self._ssh_client.copy(local_path, remote_path)
        local_path = self._context.test_source_directory/"tests"/"scripts"/"agent-service"
        remote_path = self._context.remote_working_directory/"agent-service"
        self._ssh_client.copy(local_path, remote_path)
        local_path = self._context.test_source_directory/"tests"/"scripts"/"agent-update-config"
        remote_path = self._context.remote_working_directory/"agent-update-config"
        self._ssh_client.copy(local_path, remote_path)
        self._ssh_client.run_command(f"sudo {remote_path}")

    @staticmethod
    def _verify_agent_update_flag_enabled(vm: VmMachine) -> bool:
        result: VirtualMachine = vm.get()
        flag: bool = result.os_profile.linux_configuration.enable_vm_agent_platform_updates
        if flag is None:
            return False
        return flag

    def _enable_agent_update_flag(self, vm: VmMachine) -> None:
        osprofile = {
            "location": self._context.vm.location,  # location is required field
            "properties": {
                "osProfile": {
                    "linuxConfiguration": {
                        "enableVMAgentPlatformUpdates": True
                    }
                }
            }
        }
        vm.create_or_update(osprofile)

    def _mock_rsm_update(self, requested_version: str) -> None:
        """
        This method is to simulate the rsm request.
        First we ensure the PlatformUpdates enabled in the vm and then make a request using rest api
        """
        vm: VmMachine = VmMachine(self._context.vm)
        if not self._verify_agent_update_flag_enabled(vm):
            # enable the flag
            self._enable_agent_update_flag(vm)
            log.info("Set the enableVMAgentPlatformUpdates flag to True")
        else:
            log.info("Already enableVMAgentPlatformUpdates flag set to True")

        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default")
        headers = {'Authorization': 'Bearer ' + token.token, 'Content-Type': 'application/json'}
        # Later this api call will be replaced by azure-python-sdk wrapper
        # Todo: management endpoints are different for national clouds. we need to change this.
        url = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines/{2}/" \
              "UpgradeVMAgent?api-version=2022-08-01".format(self._context.vm.subscription, self._context.vm.resource_group, self._context.vm.name)
        data = {
            "target": "Microsoft.OSTCLinuxAgent.Test",
            "targetVersion": requested_version
        }

        response = requests.post(url, data=json.dumps(data), headers=headers)
        if response.status_code == 202:
            log.info("RSM upgrade request accepted")
        else:
            raise Exception("Error occurred while RSM upgrade request. Status code : {0} and msg: {1}".format(response.status_code, response.content))

    def _verify_guest_agent_update(self, requested_version: str) -> None:
        """
        Verify current agent version running on rsm requested version
        """
        def _check_agent_version(requested_version: str) -> bool:
            stdout: str = self._ssh_client.run_command("sudo waagent --version")
            assert_that(stdout).described_as("Guest agent didn't update to requested version {0} but found \n {1}".format(requested_version, stdout))\
                .contains(f"Goal state agent: {requested_version}")
            return True

        log.info("Verifying agent updated to requested version")
        retry_if_not_found(lambda: _check_agent_version(requested_version))
        stdout: str = self._ssh_client.run_command("sudo waagent --version")
        log.info(f"Verified agent updated to requested version. Current agent version running:\n {stdout}")

    def _verify_agent_reported_supported_feature_flag(self):
        """
        RSM update rely on supported flag that agent sends to CRP.So, checking if GA reports feature flag from the agent log
        """
        def _check_agent_supports_versioning() -> bool:
            found: str = self._ssh_client.run_command("grep -q 'Agent.*supports GA Versioning' /var/log/waagent.log && echo true || echo false").rstrip()
            return True if found == "true" else False

        log.info("Verifying agent reported supported feature flag")
        found: bool = retry_if_not_found(lambda: _check_agent_supports_versioning())

        if not found:
            raise Exception("Agent failed to report supported feature flag, so skipping agent update validations")
        else:
            log.info("Successfully verified agent reported supported feature flag")


if __name__ == "__main__":
    RsmUpdateBvt.run_from_command_line()
