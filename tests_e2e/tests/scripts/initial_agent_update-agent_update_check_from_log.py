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
# Checks that the initial agent update happens before processing goal state from the agent log

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
    args, _ = parser.parse_known_args()

    agentlog = AgentLog()

    goal_state_processing_pattern = "ProcessExtensionsGoalState started"
    update_pattern = "Current Agent {0} completed all update checks, exiting current process to upgrade to the new Agent version {1}".format(args.current_version, args.latest_version)
    processing_time = datetime.time.min
    update_time = datetime.time.min

    log.info(f"Searching for initial '{goal_state_processing_pattern}' pattern in agent log")
    for record in agentlog.read():
        match = re.search(goal_state_processing_pattern, record.message, flags=re.DOTALL)
        if match is not None:
            log.info("Found data: {0} in agent log".format(record))
            processing_time = record.when
            break

    log.info(f"Searching for initial '{update_pattern}' pattern in agent log")
    for record in agentlog.read():
        match = re.search(update_pattern, record.message, flags=re.DOTALL)
        if match is not None:
            log.info("Found data: {0} in agent log".format(record))
            update_time = record.when
            break

    if update_time < processing_time:
        log.info("Verified initial agent update happened before processing goal state")
    else:
        fail("Agent initial update didn't happened before processing goal state")


if __name__ == '__main__':
    main()
