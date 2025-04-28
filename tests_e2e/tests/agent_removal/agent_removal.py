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
from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentRemoval(AgentVmTest):
    """
    This test verifies the manifest contents after agent removal from PIR.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()
        self._expected_versions = None
        self._removed_version = None
        if hasattr(context, "expected_versions") and hasattr(context, "removed_version"):
            fail("Only one of the following arguments should be provided, but both were: expected_versions, removed_version")
        elif not hasattr(context, "expected_versions") and not hasattr(context, "removed_version"):
            fail("Exactly one of the following arguments should be provided: expected_versions, removed_version")
        elif hasattr(context, "expected_versions"):
            self._expected_versions = context.expected_versions
        elif hasattr(context, "removed_version"):
            self._removed_version = context.removed_version
        self._GAFamily = context.GAFamily if hasattr(context, "GAFamily") else "Prod"

    def run(self):
        log.info('Executing agent_removal-verify_manifest_versions.py remote script to validate the manifest versions')
        if self._expected_versions is not None:
            self._run_remote_test(self._ssh_client, f"agent_removal-verify_manifest_versions.py --expected_versions '{self._expected_versions}' --ga_family '{self._GAFamily}'", use_sudo=True)
        else:
            self._run_remote_test(self._ssh_client, f"agent_removal-verify_manifest_versions.py --removed_version '{self._removed_version}' --ga_family '{self._GAFamily}'", use_sudo=True)
