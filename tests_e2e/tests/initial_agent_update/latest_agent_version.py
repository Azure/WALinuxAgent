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
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.agent_update_helpers import verify_current_agent_version
from tests_e2e.tests.lib.logging import log


class LatestAgentVersion(AgentVmTest):
    """
    This test verifies that the agent picks up the latest version based on the AutoUpdate.UpdateToLatestVersion flag.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()
        self._test_version = "2.8.9.9"

    def run(self):

        log.info("Testing daemon picks latest version when AutoUpdate.UpdateToLatestVersion=y")
        log.info("Updating AutoUpdate.UpdateToLatestVersion=y and AutoUpdate.Enabled=n")
        setup_script = (
            "agent-service stop && "
            "rm -rfv /var/lib/waagent/WALinuxAgent-* && "
            "update-waagent-conf AutoUpdate.UpdateToLatestVersion=y AutoUpdate.Enabled=n Debug.EnableGAVersioning=n Debug.SelfUpdateHotfixFrequency=90 Debug.SelfUpdateRegularFrequency=90 Autoupdate.Frequency=30")
        output: str = self._ssh_client.run_command(f"sh -c '{setup_script}'", use_sudo=True)
        log.info("Updated: %s", output)
        latest_version: str = self._ssh_client.run_command("agent_update-get_latest_version_from_manifest.py --family_type Prod",
                                                           use_sudo=True).rstrip()
        log.info("Verifying agent updated to latest version: %s from custom image test version: %s", latest_version, self._test_version)
        verify_current_agent_version(self._ssh_client, latest_version)

        log.info("Testing daemon picks latest downloaded version when AutoUpdate.UpdateToLatestVersion=n")
        log.info("Setting AutoUpdate.UpdateToLatestVersion=n and AutoUpdate.Enabled=n")
        setup_script = (
            "agent-service stop && "
            "update-waagent-conf AutoUpdate.UpdateToLatestVersion=n")
        output = self._ssh_client.run_command(f"sh -c '{setup_script}'", use_sudo=True)
        log.info("Updated: %s", output)
        log.info("Verifying agent runs on latest downloaded version: %s", latest_version)
        verify_current_agent_version(self._ssh_client, latest_version)

        log.info("Testing daemon picks installed version when only AutoUpdate.Enabled=n")
        log.info("Removing AutoUpdate.UpdateToLatestVersion")
        output = self._ssh_client.run_command("remove-waagent-conf AutoUpdate.UpdateToLatestVersion", use_sudo=True)
        log.info("Removed: %s", output)
        log.info("Verifying agent reverted to daemon version: %s", self._test_version)
        verify_current_agent_version(self._ssh_client, self._test_version)


if __name__ == "__main__":
    LatestAgentVersion.run_from_command_line()
