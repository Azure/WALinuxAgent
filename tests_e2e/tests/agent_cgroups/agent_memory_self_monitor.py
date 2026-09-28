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

from typing import List, Dict, Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class AgentMemorySelfMonitor(AgentVmTest):
    """
    E2E test for the agent's anon-memory self-monitoring + clean-exit mitigation.

    Verifies that when the agent's anonymous memory usage exceeds the configured
    quota for N consecutive checks:
      1. Consecutive-breach events are emitted.
      2. On the Nth breach, the agent evaluates guardrails and exits cleanly
         (ExitException), and the daemon restarts it.
      3. A per-version restart record is persisted to
         <lib_dir>/state/agent_memory_restart_history.json.
      4. Guardrails (max-per-version / min-interval) then block a second
         self-restart within the interval and emit the corresponding "skipped"
         telemetry/log line.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("=====Validating agent anon-memory self-monitoring and clean-exit mitigation")
        self._run_remote_test(
            self._ssh_client,
            "agent_memory_self_monitor-check_agent_self_monitoring.py",
            use_sudo=True)
        log.info("Successfully verified agent anon-memory self-monitoring behavior")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # The agent's anon-memory self-monitor logs "breach N/M" lines when
            # the anon usage exceeds Debug.AgentAnonMemoryQuota. This test may
            # legitimately trip that threshold, and the messages are expected.
            # Examples:
            #   Agent anon memory breach 1/2: [AgentMemoryExceededException] The agent anon memory limit 1 bytes exceeded. The current reported anon usage is 49721344 bytes.
            #   Agent anon memory breach 2/2: [AgentMemoryExceededException] The agent anon memory limit 1 bytes exceeded. The current reported anon usage is 49885184 bytes.
            {'message': r"Agent anon memory breach \d+/\d+.*AgentMemoryExceededException"},
            # Follow-on lines emitted by the same feature once the breach
            {'message': r"Agent anon memory breach threshold reached but self-restart skipped"},
            {'message': r"exiting due to sustained anon memory breach"},
        ]
        return ignore_rules


if __name__ == "__main__":
    AgentMemorySelfMonitor.run_from_command_line()
