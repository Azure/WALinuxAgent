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
from typing import Any, List, Dict

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.agent_update_helpers import request_rsm_update, verify_current_agent_version, \
    verify_agent_reported_supported_feature_flag
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class Rollback(AgentVmTest):
    """
    This test verifies if the agent can rollback to the previous version after an update.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def run(self):
        log.info("Testing rollback update....")
        self._prepare_agent_for_rollback()

        log.info("Retrieving the rollback version(Latest version in Prod)")
        rollback_version = self._get_latest_version()

        # At this point, vm should have been updated to published test version
        stdout: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        log.info("Current agent version running on the vm before update is \n%s", stdout)
        log.info("Attempting downgrade version %s", rollback_version)
        arch_type = self._ssh_client.get_architecture()
        request_rsm_update(rollback_version, self._context.vm, arch_type, is_downgrade=True,
                           downgrade_from=self._get_published_version())
        self._check_rsm_gs(rollback_version)
        verify_current_agent_version(self._ssh_client, rollback_version)


    def _check_rsm_gs(self, requested_version: str) -> None:
        # This checks if RSM GS available to the agent after we send the rsm update request
        log.info(
            'Executing wait_for_rsm_gs.py remote script to verify latest GS contain requested version after rsm update requested')
        self._run_remote_test(self._ssh_client, f"agent_update-wait_for_rsm_gs.py --version {requested_version}",
                              use_sudo=True)
        log.info('Verified latest GS contain requested version after rsm update requested')

    def _get_published_version(self) -> str:
        """
        Gets version from test_args if provided, else use the release version from source code version.py
        """
        if hasattr(self._context, "published_version"):
            return self._context.published_version

        version = self._ssh_client.run_command("pypy3 -c 'from azurelinuxagent.common.version import AGENT_VERSION; print(AGENT_VERSION)'").rstrip()
        return version

    def _get_latest_version(self):
        """
        Read the latest version from the test context(test_args), else use a dummy version
        """
        if hasattr(self._context, "latest_version"):
            return self._context.latest_version
        return "9.9.9.9"

    def _prepare_agent_for_rollback(self) -> None:
        """
        This method prepares the agent for the rollback update
        """
        log.info("Preparing the agent for the rollback update")
        log.info("Modifying agent update related config flags")
        output: str = self._ssh_client.run_command(
            "update-waagent-conf Debug.EnableGAVersioning=y AutoUpdate.GAFamily=Test", use_sudo=True)
        log.info('Successfully enabled rsm updates \n %s', output)

        verify_agent_reported_supported_feature_flag(self._ssh_client)


    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # This is expected as we validate the downgrade scenario
            #
            # WARNING ExtHandler ExtHandler Agent WALinuxAgent-9.9.9.9 is permanently blacklisted
            # Note: Version varies depending on the pipeline branch the test is running on
            {
                'message': rf"Agent WALinuxAgent-{self._get_published_version()} is permanently blacklisted",
            }

        ]

        return ignore_rules
