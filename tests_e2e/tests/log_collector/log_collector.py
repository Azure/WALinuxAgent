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
import re
import time

from assertpy import fail

import tests_e2e.tests.lib.logging
from azurelinuxagent.common.utils.shellutil import CommandError
from tests_e2e.tests.lib.agent_test import AgentVmTest


class LogCollector(AgentVmTest):
    """
    Tests that the log collector logs the expected behavior on periodic runs.
    """
    def run(self):
        ssh_client = self._context.create_ssh_client()
        ssh_client.run_command("update-waagent-conf Logs.Collect=y Debug.EnableCgroupV2ResourceLimiting=y Debug.LogCollectorInitialDelay=60", use_sudo=True)
        # Wait for log collector to finish uploading logs
        for _ in range(3):
            time.sleep(90)
            try:
                ssh_client.run_command("grep 'Successfully uploaded logs' /var/log/waagent.log")
                break
            except CommandError:
                tests_e2e.tests.lib.logging.log.info("The Agent has not finished log collection, will check again after a short delay")
        else:
            raise Exception("Timeout while waiting for the Agent to finish log collection")

        # Get any agent logs between log collector start and finish
        try:
            output = ssh_client.run_command(
                "sed -n " +
                "'/INFO CollectLogsHandler ExtHandler Starting log collection/, /INFO CollectLogsHandler ExtHandler Successfully uploaded logs/p' " +
                "/var/log/waagent.log").rstrip().splitlines()
        except Exception as e:
            raise Exception("Unable to get log collector logs from waagent.log: {0}".format(e))

        # These logs indicate a successful log collector run with resource enforcement and monitoring
        expected = [
            r'.*Starting log collection',
            r'.*Using cgroup v\d for resource enforcement and monitoring',
            r'.*cpu(,cpuacct)? controller for cgroup: azure-walinuxagent-logcollector \[\/sys\/fs\/cgroup(\/cpu,cpuacct)?\/azure.slice\/azure-walinuxagent.slice\/azure-walinuxagent\-logcollector.slice\/collect\-logs.scope\]',
            r'.*memory controller for cgroup: azure-walinuxagent-logcollector \[\/sys\/fs\/cgroup(\/memory)?\/azure.slice\/azure-walinuxagent.slice\/azure-walinuxagent\-logcollector.slice\/collect\-logs.scope\]',
            r'.*Log collection successfully completed',
            r'.*Successfully collected logs',
            r'.*Successfully uploaded logs'
        ]

        # Filter output to only include relevant log collector logs
        lc_logs = [log for log in output if len([pattern for pattern in expected if re.match(pattern, log)]) > 0]

        # Check that all expected logs exist and are in the correct order
        indent = lambda lines: "\n".join([f"        {ln}" for ln in lines])
        if len(lc_logs) == len(expected) and all([re.match(expected[i], lc_logs[i]) is not None for i in range(len(expected))]):
            tests_e2e.tests.lib.logging.log.info("The log collector run completed as expected.\nLog messages:\n%s", indent(lc_logs))
        else:
            fail(f"The log collector run did not complete as expected.\nExpected:\n{indent(expected)}\nActual:\n{indent(lc_logs)}")

        ssh_client.run_command("update-waagent-conf Debug.EnableCgroupV2ResourceLimiting=n Debug.LogCollectorInitialDelay=5*60",
            use_sudo=True)


if __name__ == "__main__":
    LogCollector.run_from_command_line()
