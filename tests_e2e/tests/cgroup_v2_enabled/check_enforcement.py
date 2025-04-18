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
from assertpy import assert_that

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class CheckEnforcement(AgentVmTest):
    """
    This test verifies that the agent does not enforce limits in cgroupv2 distros.
    """

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()
        #
        # 2025-04-18T21:15:37.336480Z INFO ExtHandler ExtHandler [CGI] Setting azuremonitoragent's CPUQuota to 25%
        log.info("Parsing agent log(Settings CPUQuota) on the test VM")
        output = [line for line in ssh_client.run_command("grep -E 'INFO ExtHandler.*(Setting|Resetting).*CPUQuota' /var/log/waagent.log | head").strip().split('\n') if line]

        assert_that(len(output) == 0).described_as("The agent log should not contain matching records of cpu quota being set. Output from the agent log:\n\t\t{0}".format('\n\t\t'.join(output))).is_true()
        log.info("The agent log indicates that agent does not enforce limits in cgroupv2 distros")
