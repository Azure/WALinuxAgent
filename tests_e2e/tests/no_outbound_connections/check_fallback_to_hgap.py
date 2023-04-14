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

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class NoOutboundConnections(AgentTest):
    """
    """
    def run(self):
        # 2023-04-14T14:49:43.005530Z INFO ExtHandler ExtHandler Default channel changed to HostGAPlugin channel.
        # 2023-04-14T14:49:44.625061Z INFO ExtHandler [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.25.2] Target handler state: enabled [incarnation_2]

        ssh_client: SshClient = self._context.create_ssh_client()
        log.info("Parsing agent log on the test VM")
        output = ssh_client.run_command("grep -E 'INFO ExtHandler.*(Default channel changed to HostGAPlugin)|(Target handler state:)' /var/log/waagent.log | head").split('\n')
        log.info("Output (first 10 lines) from the agent log:\n\t\t%s", '\n\t\t'.join(output))

        assert_that(len(output) > 1).is_true().described_as(
            "The agent log should contain multiple matching records"
        )
        assert_that(output[0]).contains("Default channel changed to HostGAPlugin").described_as(
            "The agent log should contain a record indicating that the default channel was changed to HostGAPlugin before executing any extensions"
        )

        log.info("The agent log indicates that the default channel was changed to HostGAPlugin before executing any extensions")


if __name__ == "__main__":
    NoOutboundConnections.run_from_command_line()

