#!/usr/bin/env pypy3

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
# Checks that the initial agent update happens with self-update before processing goal state from the agent log

import argparse
import datetime
import re

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current_version", dest='current_version', required=True)
    parser.add_argument("--latest_version", dest='latest_version', required=True)
    args = parser.parse_args()

    agentlog = AgentLog()
    patterns = {
        "goal_state": "ProcessExtensionsGoalState started",
        "self_update": f"Self-update is ready to upgrade the new agent: {args.latest_version} now before processing the goal state",
        "exit_process": f"Current Agent {args.current_version} completed all update checks, exiting current process to upgrade to the new Agent version {args.latest_version}"
    }
    first_occurrence_times = {"goal_state": datetime.time.min, "self_update": datetime.time.min, "exit_process": datetime.time.min}

    for record in agentlog.read():
        for key, pattern in patterns.items():
            # Skip if we already found the first occurrence of the pattern
            if first_occurrence_times[key] != datetime.time.min:
                continue
            if re.search(pattern, record.message, flags=re.DOTALL):
                log.info(f"Found data: {record} in agent log")
                first_occurrence_times[key] = record.when
                break

    if first_occurrence_times["self_update"] < first_occurrence_times["goal_state"] and first_occurrence_times["exit_process"] < first_occurrence_times["goal_state"]:
        log.info("Verified initial agent update happened before processing goal state")
    else:
        fail(f"Agent initial update didn't happen before processing goal state and first_occurrence_times for patterns: {patterns} are: {first_occurrence_times}")


if __name__ == '__main__':
    main()
