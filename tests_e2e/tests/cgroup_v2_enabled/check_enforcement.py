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
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class CheckEnforcement(AgentVmTest):
    """
    This test verifies that the agent has no CPU limits in cgroupv2 distros.
    """

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        log.info("Verifying CPU quota not set in the agent cgroup")
        self._run_remote_test(ssh_client, "cgroup_v2_enabled-check_quota.py", use_sudo=True)
        log.info("Verified CPU quota not set in the agent cgroup")
