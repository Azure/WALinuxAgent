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
# BVT for the agent update scenario (RSM path) with signature validation
#
# Extends the standard RSM update test to additionally verify:
#   1. Agent package signature was validated before each update where a download occurred
#   2. Goal state signature telemetry was sent on each new goal state
#
from tests_e2e.tests.agent_update.rsm_update import RsmUpdateBvt
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class RsmUpdateWithSignatureBvt(RsmUpdateBvt):

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._latest_manifest_versions = self._get_latest_manifest_versions()

    def _prepare_agent(self) -> None:
        """
        Extends the base to also enable agent signature validation, which is disabled by default.
        """
        super()._prepare_agent()
        log.info("Enabling agent signature validation for CVM test")
        output: str = self._ssh_client.run_command(
            "update-waagent-conf Debug.EnableAgentSignatureValidation=y Debug.SignatureValidationInitialDelay=0", use_sudo=True)
        log.info('Successfully enabled agent signature validation \n %s', output)

    def _run_downgrade_scenario(self, arch_type: str) -> None:
        super()._run_downgrade_scenario(arch_type)
        # Downgrade downloads a new agent package, so signature should be validated
        self._verify_agent_signature_validated(self._downgrade_version)
        self._verify_gs_signature_telemetry(rsm_requested_version=self._downgrade_version)

    def _run_upgrade_scenario(self, arch_type: str) -> None:
        super()._run_upgrade_scenario(arch_type)
        # Upgrade downloads a new agent package, so signature should be validated
        upgrade_version = "2.3.16.1"
        self._verify_agent_signature_validated(upgrade_version)
        self._verify_gs_signature_telemetry(rsm_requested_version=upgrade_version)

    def _run_no_update_scenario(self, arch_type: str) -> None:
        super()._run_no_update_scenario(arch_type)
        # No download happens in this scenario (agent already on disk), so we only verify GS telemetry
        current_version = "2.3.16.1"
        self._verify_gs_signature_telemetry(rsm_requested_version=current_version)

    # Disable pylint warning about useless parent or super() delegation in this method. Once the TODO in this method is
    # addressed, remove the pylint warning disablement
    def _run_below_daemon_scenario(self, arch_type: str) -> None:   # pylint: disable=W0246
        super()._run_below_daemon_scenario(arch_type)
        # TODO: Once signingInfo changes are implemented, publish a version of the agent with signature which is lower
        # than the daemon version for this scenario and uncomment the below lines
        # No download happens in this scenario, so we only verify GS telemetry
        # requested_version = "1.5.0.0"
        # self._verify_gs_signature_telemetry(rsm_requested_version=requested_version)

    def _verify_agent_signature_validated(self, version: str) -> None:
        log.info("Verifying agent package signature was validated for version %s", version)
        self._run_remote_test(
            self._ssh_client,
            f"agent_update-check_agent_signature_validated.py --version {version}",
            use_sudo=True)
        log.info("Successfully verified agent signature validated for version %s", version)

    def _get_latest_manifest_versions(self) -> list:
        """
        Retrieves the latest two versions from the agent manifest.
        """
        log.info("Fetching latest two versions from the agent manifest to use for goal state comparison later...")
        output: str = self._ssh_client.run_command(
            "agent_update-get_latest_version_from_manifest.py --all", use_sudo=True).rstrip()
        versions = output.split()
        latest_manifest_versions = versions[-2:]
        log.info("Latest two manifest versions: %s", latest_manifest_versions)
        return latest_manifest_versions

    def _verify_gs_signature_telemetry(self, rsm_requested_version: str = None) -> None:
        log.info("Verifying goal state signature telemetry")
        cmd = "agent_update-check_gs_signature_telemetry.py --latest-versions {0}".format(
            " ".join(self._latest_manifest_versions))
        if rsm_requested_version is not None:
            cmd += f" --rsm-requested-version {rsm_requested_version}"
        self._run_remote_test(
            self._ssh_client,
            cmd,
            use_sudo=True)
        log.info("Successfully verified goal state signature telemetry")


if __name__ == "__main__":
    RsmUpdateWithSignatureBvt.run_from_command_line()
