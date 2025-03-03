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
# Writes the last goal state processed line in the log to stdout
#
import re
import sys

from tests_e2e.tests.lib.agent_log import AgentLog


def main():
    gs_completed_regex = r"ProcessExtensionsGoalState completed\s\[[a-z_\d]{13,14}\s\d+\sms\]"
    last_gs_processed = None
    agent_log = AgentLog()

    try:
        for agent_record in agent_log.read():
            gs_complete = re.match(gs_completed_regex, agent_record.message)

            if gs_complete is not None:
                last_gs_processed = agent_record.text

    except IOError as e:
        print("Unable to get last goal state processed: {0}".format(str(e)))

    print(last_gs_processed)
    sys.exit(0)


if __name__ == "__main__":
    main()
