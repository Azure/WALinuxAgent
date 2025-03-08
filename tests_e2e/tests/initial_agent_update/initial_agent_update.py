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
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


class InitialAgentUpdate(AgentVmTest):
    """
    This test verifies that the Agent does initial update on very first goal state before it starts processing extensions for new vms that are enrolled into RSM
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()
        self._test_version = "2.8.9.9"

    def run(self):

        log.info("Testing initial agent update for new vms that are enrolled into RSM")

        log.info("Retrieving latest version from goal state to verify initial agent update")
        latest_version: str = self._ssh_client.run_command("agent_update-get_latest_version_from_manifest.py --family_type Prod",
                                                           use_sudo=True).rstrip()
        log.info("Latest Version: %s", latest_version)
        self._verify_agent_updated_to_latest_version(latest_version)
        self._verify_agent_updated_before_processing_goal_state(latest_version)

    def _verify_agent_updated_to_latest_version(self, latest_version: str) -> None:
        """
        Verifies the agent updated to latest version from custom image test version.
        """
        log.info("Verifying agent updated to latest version: {0} from custom image test version: {1}".format(latest_version, self._test_version))
        self._verify_guest_agent_update(latest_version)

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

        log.info("Running waagent --version and checking Goal state agent version")
        success: bool = retry_if_false(lambda: _check_agent_version(latest_version), delay=60)
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        if not success:
            fail("Guest agent didn't update to latest version {0} but found \n {1}".format(
                latest_version, waagent_version))
        log.info(
            f"Successfully verified agent updated to latest version. Current agent version running:\n {waagent_version}")

    def _verify_agent_updated_before_processing_goal_state(self, latest_version) -> None:
        log.info("Checking agent log if agent does initial update with self-update before processing goal state")

        output = self._ssh_client.run_command(
            "initial_agent_update-agent_update_check_from_log.py --current_version {0} --latest_version {1}".format(self._test_version, latest_version))
        log.info(output)
