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

from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.agent_update_helpers import build_agent_package
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


class SelfUpdateBvt(AgentVmTest):
    """
    This test case is to verify that the agent can update itself to the latest version using self-update path when vm not enrolled to RSM updates
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()
        self._test_version = "2.8.9.9"
        self._test_pkg_name = f"WALinuxAgent-{self._test_version}.zip"
        self._latest_version = ""

    def run(self):
        log.info("Verifying agent updated to latest version from custom test version")
        self._test_setup()
        self._verify_agent_updated_to_latest_version()

        log.info("Verifying agent remains on custom test version when AutoUpdate.UpdateToLatestVersion=n")
        self._test_setup_and_update_to_latest_version_false()
        self._verify_agent_remains_on_custom_test_version()

    def _test_setup(self) -> None:
        """
        Builds the custom test agent pkg as some lower version and installs it on the vm
        """
        build_agent_package(self._context.working_directory, self._test_version, self._ssh_client, self._context.vm)
        output: str = self._ssh_client.run_command(
            f"agent_update-self_update_test_setup --package ~/tmp/{self._test_pkg_name} --version {self._test_version} --update_to_latest_version y",
            use_sudo=True)
        log.info("Successfully installed custom test agent pkg version \n%s", output)

    def _verify_agent_updated_to_latest_version(self) -> None:
        """
        Verifies the agent updated to latest version from custom test version.
        We retrieve latest version from goal state and compare with current agent version running as that latest version
        """
        self._latest_version = self._ssh_client.run_command("agent_update-get_latest_version_from_manifest.py",
                                                           use_sudo=True).rstrip()
        self._verify_guest_agent_update(self._latest_version)
        # Verify agent updated to latest version by custom test agent
        self._ssh_client.run_command(
            "agent_update-self_update_check.py --latest-version {0} --current-version {1}".format(self._latest_version,
                                                                                                  self._test_version))

    def _verify_guest_agent_update(self, latest_version: str) -> None:
        """
        Verify current agent version running on latest version
        """

        def _check_agent_version(latest_version: str) -> bool:
            waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
            expected_version = f"Goal state agent: {latest_version}"
            if expected_version in waagent_version:
                return True
            else:
                return False

        log.info("Verifying agent updated to latest version: {0}".format(latest_version))
        success: bool = retry_if_false(lambda: _check_agent_version(latest_version), delay=60)
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        if not success:
            fail("Guest agent didn't update to latest version {0} but found \n {1}".format(
                latest_version, waagent_version))
        log.info(
            f"Successfully verified agent updated to latest version. Current agent version running:\n {waagent_version}")

    def _test_setup_and_update_to_latest_version_false(self) -> None:
        """
        Builds the custom test agent pkg as some lower version and installs it on the vm
        Also modify the configuration AutoUpdate.UpdateToLatestVersion=n
        """
        build_agent_package(self._context.working_directory, self._test_version, self._ssh_client, self._context.vm)
        output: str = self._ssh_client.run_command(
            f"agent_update-self_update_test_setup --package ~/tmp/{self._test_pkg_name} --version {self._test_version} --update_to_latest_version n",
            use_sudo=True)
        log.info("Successfully installed custom test agent pkg version \n%s", output)

    def _verify_agent_remains_on_custom_test_version(self) -> None:
        """
        Verifies the agent remains on custom test version when UpdateToLatestVersion=n
        """

        def _check_agent_version(version: str) -> bool:
            waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
            expected_version = f"Goal state agent: {version}"
            if expected_version in waagent_version:
                return True
            else:
                return False

        waagent_version: str = ""
        log.info("Verifying if current agent on version: {0}".format(self._test_version))
        success: bool = retry_if_false(lambda: _check_agent_version(self._test_version), delay=60)
        if not success:
            fail("Guest agent was on different version than expected version {0} and found \n {1}".format(
                self._test_version, waagent_version))
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info(
            f"Successfully verified agent stayed on test version. Current agent version running:\n {waagent_version}")


if __name__ == "__main__":
    SelfUpdateBvt.run_from_command_line()
