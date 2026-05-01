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
# BVT for the agent update scenario (self-update path) with signature validation
#
# Extends the standard self-update test to additionally verify:
#   1. Agent package signature was validated before the self-update
#   2. Goal state signature telemetry was sent on new goal states
#
from tests_e2e.tests.agent_update.self_update import SelfUpdateBvt
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class SelfUpdateWithSignatureBvt(SelfUpdateBvt):

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._latest_manifest_versions = self._get_latest_manifest_versions()

    def _test_setup(self) -> None:
        """
        Extends the base setup to also enable agent signature validation, which is disabled by default.
        """
        log.info("Enabling agent signature validation for CVM test")
        output: str = self._ssh_client.run_command(
            "update-waagent-conf Debug.EnableAgentSignatureValidation=y Debug.SignatureValidationInitialDelay=0",
            use_sudo=True)
        log.info('Successfully enabled agent signature validation \n %s', output)
        super()._test_setup()

    def _verify_agent_updated_to_latest_version(self) -> None:
        """
        Extends the base verification to also check that agent package signature was validated and
        goal state signature telemetry was sent.
        """
        super()._verify_agent_updated_to_latest_version()
        self._verify_agent_signature_validated(self._latest_version)
        self._verify_gs_signature_telemetry()

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

    def _verify_gs_signature_telemetry(self) -> None:
        log.info("Verifying goal state signature telemetry")
        cmd = "agent_update-check_gs_signature_telemetry.py --latest-versions {0}".format(
            " ".join(self._latest_manifest_versions))
        self._run_remote_test(
            self._ssh_client,
            cmd,
            use_sudo=True)
        log.info("Successfully verified goal state signature telemetry")


if __name__ == "__main__":
    SelfUpdateWithSignatureBvt.run_from_command_line()
