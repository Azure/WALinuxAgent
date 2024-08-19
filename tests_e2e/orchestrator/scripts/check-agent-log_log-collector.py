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
import json
import re
import sys
from datetime import timedelta

from pathlib import Path

from tests_e2e.tests.lib.agent_log import AgentLog

# Checks the agent log for unsuccessful log collector runs. If an unsuccessful run is detected, prints all the
# log collector log records for the unsucessful run.

try:
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', help='Path of the log file', default='/var/log/waagent.log')
    parser.add_argument('-j', '--json', action='store_true', help='Produce a JSON report')
    parser.set_defaults(json=False)
    args = parser.parse_args()

    logcollector_start_regex = r"Running log collector mode normal"
    logcollector_completed_regex = r"Log collection successfully completed"
    logcollector_records = []
    agent_log = AgentLog(Path(args.path))

    logcollector_start = None
    last_recorded_timestamp = None
    logcollector_completed = False

    for record in agent_log.read():
        last_recorded_timestamp = record.timestamp
        if record.prefix == "LogCollector":
            logcollector_records.append(record)
        if re.match(logcollector_start_regex, record.message):
            logcollector_start = record.timestamp
            continue
        if re.match(logcollector_completed_regex, record.message):
            logcollector_completed = True
            break

    # No issues are detected if:
    #   - there weren't any log collector runs, or
    #   - there was a successful log collector run, or
    #   - a log collector run started less than 5 seconds before the last agent log record (log collector may not have had enough time to complete)
    if logcollector_start is None or logcollector_completed or (last_recorded_timestamp - logcollector_start < timedelta(seconds=5)):
        logcollector_records = []

    if args.json:
        print(json.dumps(logcollector_records, default=lambda o: o.__dict__))
    else:
        if len(logcollector_records) == 0:
            print("No issues with the log collector were detected.")
        else:
            for record in logcollector_records:
                print(record.text)

except Exception as e:
    print(f"{e}", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
