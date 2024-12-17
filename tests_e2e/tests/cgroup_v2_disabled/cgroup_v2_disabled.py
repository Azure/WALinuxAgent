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
import time

from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


class Cgroupv2Disabled(AgentVmTest):
    """
    The test verifies that the agent does not enable resource enforcement and monitoring on machines which are using
    cgroup v2. It also checks that the agent correctly determined the controller mount points. This test will be
    removed once cgroup v2 is supported.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def check_agent_log_contains(self, data, assertion):
        try:
            self._ssh_client.run_command("grep \"{0}\" /var/log/waagent.log".format(data))
        except CommandError:
            fail("{0}".format(assertion))

    def run(self):
        # Cgroup configurator is initialized when agent is started, and before the goal state processing period is
        # logged. Wait until the agent logs the goal state period before checking for cgroup initialization logs.
        log.info("Wait for cgroup configurator to be initialized...")
        for _ in range(15):
            try:
                self._ssh_client.run_command("grep 'Goal State Period:' /var/log/waagent.log")
                break
            except CommandError:
                log.info("The Agent has not initialized cgroups yet, will check again after a short delay")
                time.sleep(60)
        else:
            raise Exception("Timeout while waiting for the Agent to initialize cgroups")

        # Verify that the agent chose v2 for resource enforcement and monitoring
        log.info("")
        log.info("Checking that the agent chose cgroup v2 api for resource enforcement and monitoring...")
        self.check_agent_log_contains('Using cgroup v2 for resource enforcement and monitoring', 'The agent should choose v2 for api resource enforcement and monitoring')

        # Verify that the agent does not support cgroup v2
        log.info("")
        log.info("Checking that the agent does not use cgroup v2 for resource enforcement and monitoring...")
        self.check_agent_log_contains('Agent and extensions resource enforcement and monitoring is not currently supported on cgroup v2',
                                      'The agent should not attempt to use cgroup v2 for resource enforcement and monitoring')
        self.check_agent_log_contains('Agent cgroups enabled: False',
                                      'The agent should not enable cgroups when system is using v2')


if __name__ == "__main__":
    Cgroupv2Disabled.run_from_command_line()
