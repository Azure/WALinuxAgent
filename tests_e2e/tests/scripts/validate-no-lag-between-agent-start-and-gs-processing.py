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

import argparse
from datetime import timedelta
import re
import sys

from pathlib import Path
from tests_e2e.tests.lib.agent_log import AgentLog


def main():
    success = True

    agent_started_time = []
    agent_msg = []
    time_diff_max_secs = 15

    # Example: Agent WALinuxAgent-2.2.47.2 is running as the goal state agent
    agent_started_regex = r"Azure Linux Agent \(Goal State Agent version [0-9.]+\)"
    gs_completed_regex = r"ProcessExtensionsGoalState completed\s\[(?P<id>[a-z_\d]+)\s(?P<duration>\d+)\sms\]"

    verified_atleast_one_log_line = False
    verified_atleast_one_agent_started_log_line = False
    verified_atleast_one_gs_complete_log_line = False

    agent_log = AgentLog(Path('/var/log/waagent.log'))

    try:
        for agent_record in agent_log.read():
            verified_atleast_one_log_line = True

            agent_started = re.match(agent_started_regex, agent_record.message)
            verified_atleast_one_agent_started_log_line = verified_atleast_one_agent_started_log_line or agent_started
            if agent_started:
                agent_started_time.append(agent_record.timestamp)
                agent_msg.append(agent_record.message)

            gs_complete = re.match(gs_completed_regex, agent_record.message)
            verified_atleast_one_gs_complete_log_line = verified_atleast_one_gs_complete_log_line or gs_complete
            if agent_started_time and gs_complete:
                duration = gs_complete.group('duration')
                diff = agent_record.timestamp - agent_started_time.pop()
                # Reduce the duration it took to complete the Goalstate, essentially we should only care about how long
                # the agent took after start/restart to start processing GS
                diff -= timedelta(milliseconds=int(duration))
                agent_msg_line = agent_msg.pop()
                if diff.seconds > time_diff_max_secs:
                    success = False
                    print("Found delay between agent start and GoalState Processing > {0}secs: "
                             "Messages: \n {1} {2}".format(time_diff_max_secs, agent_msg_line, agent_record.message))

    except IOError as e:
        print("Unable to validate no lag time: {1}".format(str(e)))

    if not verified_atleast_one_log_line:
        success = False
        print("Didn't parse a single log line, ensure the log_parser is working fine and verify log regex")

    if not verified_atleast_one_agent_started_log_line:
        success = False
        print("Didn't parse a single agent started log line, ensure the Regex is working fine: {0}"
              .format(agent_started_regex))

    if not verified_atleast_one_gs_complete_log_line:
        success = False
        print("Didn't parse a single GS completed log line, ensure the Regex is working fine: {0}"
              .format(gs_completed_regex))

    if agent_started_time or agent_msg:
        success = False
        print("Mismatch between number of agent start messages and number of GoalState Processing messages\n "
              "Agent Start Messages: \n {0}".format('\n'.join(agent_msg)))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()