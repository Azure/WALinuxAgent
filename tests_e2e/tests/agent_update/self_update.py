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

import os
from pathlib import Path
from threading import RLock

from assertpy import fail

import azurelinuxagent
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false
from tests_e2e.tests.lib.shell import run_command


class SelfUpdateBvt(AgentVmTest):
    """
    This test case is to verify that the agent can update itself to the latest version using self-update path when vm not enrolled to RSM updates
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()
        self._test_version = "2.8.9.9"
        self._test_pkg_name = f"WALinuxAgent-{self._test_version}.zip"

    _setup_lock = RLock()

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
        self._build_custom_test_agent()
        output: str = self._ssh_client.run_command(
            f"agent_update-self_update_test_setup --package ~/tmp/{self._test_pkg_name} --version {self._test_version} --update_to_latest_version y",
            use_sudo=True)
        log.info("Successfully installed custom test agent pkg version \n%s", output)

    def _build_custom_test_agent(self) -> None:
        """
        Builds the custom test pkg
        """
        with self._setup_lock:
            agent_source_path: Path = self._context.working_directory / "source"
            source_pkg_path: Path = agent_source_path / "eggs" / f"{self._test_pkg_name}"
            if source_pkg_path.exists():
                log.info("The test pkg already exists at %s, skipping build", source_pkg_path)
            else:
                if agent_source_path.exists():
                    os.rmdir(agent_source_path)  # Remove if partial build exists
                source_directory: Path = Path(azurelinuxagent.__path__[0]).parent
                copy_cmd: str = f"cp -r {source_directory} {agent_source_path}"
                log.info("Copying agent source %s to %s", source_directory, agent_source_path)
                run_command(copy_cmd, shell=True)
                if not agent_source_path.exists():
                    raise Exception(
                        f"The agent source was not copied to the expected path {agent_source_path}")
                version_file: Path = agent_source_path / "azurelinuxagent" / "common" / "version.py"
                version_cmd = rf"""sed -E -i "s/^AGENT_VERSION\s+=\s+'[0-9.]+'/AGENT_VERSION = '{self._test_version}'/g" {version_file}"""
                log.info("Setting agent version to %s to build new pkg", self._test_version)
                run_command(version_cmd, shell=True)
                makepkg_file: Path = agent_source_path / "makepkg.py"
                build_cmd: str = f"env PYTHONPATH={agent_source_path} python3 {makepkg_file} -o {agent_source_path}"
                log.info("Building custom test agent pkg version %s", self._test_version)
                run_command(build_cmd, shell=True)
                if not source_pkg_path.exists():
                    raise Exception(
                        f"The test pkg was not created at the expected path {source_pkg_path}")
            target_path: Path = Path("~") / "tmp"
            log.info("Copying %s to %s:%s", source_pkg_path, self._context.vm, target_path)
            self._ssh_client.copy_to_node(source_pkg_path, target_path)

    def _verify_agent_updated_to_latest_version(self) -> None:
        """
        Verifies the agent updated to latest version from custom test version.
        We retrieve latest version from goal state and compare with current agent version running as that latest version
        """
        latest_version: str = self._ssh_client.run_command("agent_update-self_update_latest_version.py",
                                                           use_sudo=True).rstrip()
        self._verify_guest_agent_update(latest_version)
        # Verify agent updated to latest version by custom test agent
        self._ssh_client.run_command(
            "agent_update-self_update_check.py --latest-version {0} --current-version {1}".format(latest_version,
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

        waagent_version: str = ""
        log.info("Verifying agent updated to latest version: {0}".format(latest_version))
        success: bool = retry_if_false(lambda: _check_agent_version(latest_version), delay=60)
        if not success:
            fail("Guest agent didn't update to latest version {0} but found \n {1}".format(
                latest_version, waagent_version))
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info(
            f"Successfully verified agent updated to latest version. Current agent version running:\n {waagent_version}")

    def _test_setup_and_update_to_latest_version_false(self) -> None:
        """
        Builds the custom test agent pkg as some lower version and installs it on the vm
        Also modify the configuration AutoUpdate.UpdateToLatestVersion=n
        """
        self._build_custom_test_agent()
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
