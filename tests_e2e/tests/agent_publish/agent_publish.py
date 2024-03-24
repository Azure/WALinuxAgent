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
import uuid
from datetime import datetime

from assertpy import fail

from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.agent_update_helpers import request_rsm_update
from tests_e2e.tests.lib.retry import retry_if_false
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class AgentPublishTest(AgentVmTest):
    """
    This script verifies if the agent update performed in the vm.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()
        self._published_version = self._get_published_version()

    def run(self):
        """
        we run the scenario in the following steps:
            1. Print the current agent version before the update
            2. Prepare the agent for the update
            3. Check for agent update from the log and waagent version
            4. Ensure CSE is working
        """
        self._get_agent_info()

        log.info("Testing rsm update flow....")
        self._prepare_agent_for_rsm_update()
        self._check_update_from_log()
        self._verify_current_agent_version()
        self._check_cse()

        log.info("Testing self update flow....")
        self._prepare_agent_for_self_update()
        self._check_update_from_log()
        self._verify_current_agent_version()

        self._check_cse()

    def get_ignore_errors_before_timestamp(self) -> datetime:
        timestamp = self._ssh_client.run_command("agent_publish-get_agent_log_record_timestamp.py")
        return datetime.strptime(timestamp.strip(), u'%Y-%m-%d %H:%M:%S.%f')

    def _get_published_version(self):
        """
        Get the published version that needs to be validated
        Read from test_args if provided, else use the release version from version.py
        """
        if hasattr(self._context, "published_version"):
            return self._context.published_version
        return AGENT_VERSION

    def _get_agent_info(self) -> None:
        stdout: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info('Agent info \n%s', stdout)

    def _verify_agent_reported_supported_feature_flag(self):
        """
        RSM update rely on supported feature flag that agent sends to CRP.So, checking if GA reports feature flag from reported status
        """
        log.info(
            "Executing verify_versioning_supported_feature.py remote script to verify agent reported supported feature flag, so that CRP can send RSM update request")
        self._run_remote_test(self._ssh_client, "agent_update-verify_versioning_supported_feature.py", use_sudo=True)
        log.info("Successfully verified that Agent reported VersioningGovernance supported feature flag")

    def _check_rsm_gs(self, requested_version: str) -> None:
        # This checks if RSM GS available to the agent after we send the rsm update request
        log.info(
            'Executing wait_for_rsm_gs.py remote script to verify latest GS contain requested version after rsm update requested')
        self._run_remote_test(self._ssh_client, f"agent_update-wait_for_rsm_gs.py --version {requested_version}",
                              use_sudo=True)
        log.info('Verified latest GS contain requested version after rsm update requested')

    def _prepare_agent_for_rsm_update(self) -> None:
        """
        This method prepares the agent for the RSM update
        """
        # First we update the agent to latest version like prod
        # Next send RSM update request for new published test version
        log.info(
            'Updating agent config flags to allow and download test versions')
        output: str = self._ssh_client.run_command(
                              "update-waagent-conf AutoUpdate.Enabled=y AutoUpdate.UpdateToLatestVersion=y", use_sudo=True)
        log.info('Successfully updated agent update config \n %s', output)

        self._verify_agent_reported_supported_feature_flag()
        arch_type = self._ssh_client.get_architecture()
        request_rsm_update(self._published_version, self._context.vm, arch_type)
        self._check_rsm_gs(self._published_version)

        output: str = self._ssh_client.run_command(
                              "update-waagent-conf Debug.EnableGAVersioning=y AutoUpdate.GAFamily=Test", use_sudo=True)
        log.info('Successfully enabled rsm updates \n %s', output)

    def _prepare_agent_for_self_update(self) -> None:
        """
        This method prepares the agent for the self update
        """
        log.info("Modifying agent update related config flags and renaming the log file")
        setup_script = ("agent-service stop &&  mv /var/log/waagent.log /var/log/waagent.$(date --iso-8601=seconds).log && "
                        "rm -rf /var/lib/waagent/WALinuxAgent-* && "
                        "update-waagent-conf AutoUpdate.UpdateToLatestVersion=y AutoUpdate.GAFamily=Test AutoUpdate.Enabled=y Extensions.Enabled=y Debug.EnableGAVersioning=n")
        self._run_remote_test(self._ssh_client, f"sh -c '{setup_script}'", use_sudo=True)
        log.info('Renamed log file and updated self-update config flags')

    def _check_update_from_log(self) -> None:
        log.info("Verifying for agent update status")
        self._run_remote_test(self._ssh_client, f"agent_publish-check_update.py --published-version {self._published_version}")
        log.info('Successfully checked the agent update')

    def _verify_current_agent_version(self) -> None:
        """
        Verify current agent version running on published version
        """

        def _check_agent_version(version: str) -> bool:
            waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
            expected_version = f"Goal state agent: {version}"
            if expected_version in waagent_version:
                return True
            else:
                return False

        waagent_version: str = ""
        log.info("Verifying agent updated to published version: {0}".format(self._published_version))
        success: bool = retry_if_false(lambda: _check_agent_version(self._published_version))
        if not success:
            fail("Guest agent didn't update to published version {0} but found \n {1}. \n ".format(
                self._published_version, waagent_version))
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info(
            f"Successfully verified agent updated to published version. Current agent version running:\n {waagent_version}")

    def _check_cse(self) -> None:
        custom_script_2_1 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"),
            resource_name="CustomScript")

        log.info("Installing %s", custom_script_2_1)
        message = f"Hello {uuid.uuid4()}!"
        custom_script_2_1.enable(
            settings={
                'commandToExecute': f"echo \'{message}\'"
            },
            auto_upgrade_minor_version=False
        )
        custom_script_2_1.assert_instance_view(expected_version="2.1", expected_message=message)


if __name__ == "__main__":
    AgentPublishTest.run_from_command_line()
