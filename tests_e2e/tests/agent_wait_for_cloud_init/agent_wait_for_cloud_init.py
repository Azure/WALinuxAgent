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
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentWaitForCloudInit(AgentVmTest):
    """
    This test verifies that the Agent waits for cloud-init to complete before it starts processing extensions.

    To do this, it adds 'CloudInitScript' in cloud-init's custom data. The script ensures first that the Agent
    is waiting for cloud-init, and then sleeps for a couple of minutes before completing. The scripts appends
    a set of known messages to waagent.log, and the test simply verifies that the messages are present in the
    log in the expected order, and that they occur before the Agent reports that it is processing extensions.
    """
    CloudInitScript = """#!/usr/bin/env bash
        set -euox pipefail
    
        echo ">>> $(date) cloud-init script begin" >> /var/log/waagent.log
        while ! grep 'Waiting for cloud-init to complete' /var/log/waagent.log; do
            sleep 15
        done
        echo ">>> $(date) The Agent is waiting for cloud-init, will pause for a couple of minutes" >> /var/log/waagent.log
        sleep 120
        echo ">>> $(date) cloud-init script end" >> /var/log/waagent.log
    """

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        log.info("Waiting for Agent to start processing extensions")
        for _ in range(15):
            try:
                ssh_client.run_command("grep 'ProcessExtensionsGoalState started' /var/log/waagent.log")
                break
            except CommandError:
                log.info("The Agent has not started to process extensions, will check again after a short delay")
                time.sleep(60)
        else:
            raise Exception("Timeout while waiting for the Agent to start processing extensions")

        log.info("The Agent has started to process extensions")

        output = ssh_client.run_command(
            "grep -E '^>>>|" +
                "INFO ExtHandler ExtHandler cloud-init completed|" +
                "INFO ExtHandler ExtHandler ProcessExtensionsGoalState started' /var/log/waagent.log")

        output = output.rstrip().splitlines()

        expected = [
            'cloud-init script begin',
            'The Agent is waiting for cloud-init, will pause for a couple of minutes',
            'cloud-init script end',
            'cloud-init completed',
            'ProcessExtensionsGoalState started'
        ]

        indent = lambda lines: "\n".join([f"        {ln}" for ln in lines])
        if len(output) == len(expected) and all([expected[i] in output[i] for i in range(len(expected))]):
            log.info("The Agent waited for cloud-init before processing extensions.\nLog messages:\n%s", indent(output))
        else:
            fail(f"The Agent did not wait for cloud-init before processing extensions.\nExpected:\n{indent(expected)}\nActual:\n{indent(output)}")


if __name__ == "__main__":
    AgentWaitForCloudInit.run_from_command_line()

