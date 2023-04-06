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
import sys

from pathlib import Path
from tests_e2e.tests.lib.agent_log import AgentLog

try:
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', help='Path of the log file', default='/var/log/waagent.log')
    parser.add_argument('-j', '--json', action='store_true', help='Produce a JSON report')
    parser.set_defaults(json=False)
    args = parser.parse_args()

    error_list = AgentLog(Path(args.path)).get_errors()

    if args.json:
        print(json.dumps(error_list, default=lambda o: o.__dict__))
    else:
        if len(error_list) == 0:
            print("No errors were found.")
        else:
            for e in error_list:
                print(e.text)

except Exception as e:
    print(f"{e}", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
