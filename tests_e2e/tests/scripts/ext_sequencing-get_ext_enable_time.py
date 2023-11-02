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
# Gets the timestamp for when the provided extension was enabled
#

import argparse
import re
import sys

from datetime import datetime
from pathlib import Path


def main():
    """
    Returns the timestamp of when the provided extension was enabled
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--ext_type", dest='ext_type', required=True)
    parser.add_argument("--start_time", dest='start_time', required=True)
    args, _ = parser.parse_known_args()

    # Extension enabled time is in extension CommandExecution.log
    command_exec_log_path = Path('/var/log/azure/' + args.ext_type + '/CommandExecution.log')
    command_exec_log = open(command_exec_log_path, 'r')
    enabled_match = None
    for line in command_exec_log.readlines():
        line = line.rstrip()
        if args.ext_type == "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent":
            # AMA logs enable succeeded and its timestamp to the command execution log:
            # 2023-11-01T23:22:53.124603Z INFO ExtHandler [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.28.11] Command: ./shim.sh -enable
            # [stdout]
            # 2023/09/26 04:07:33 [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.28.5] Enable,success,0,Enable succeeded
            enable_pattern = r'.*(?P<timestamp>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[Microsoft\.Azure\.Monitor\.AzureMonitorLinuxAgent\-.*] .*Enable succeeded.*'
            match = re.match(enable_pattern, line)
            if match:
                enabled_match = match
        else:
            # For RC and CSE, we can determine when enable succeeded from the stdout of the enable command execution from
            # the command execution log:
            # 2023-09-26T04:07:39.042948Z INFO ExtHandler [Microsoft.CPlat.Core.RunCommandLinux-1.0.5] Command: bin/run-command-shim enable
            # [stdout]
            # ...
            # time=2023-09-26T04:07:37Z version=v1.0.4/git@b3be41d-dirty operation=enable seq=0 event=enabledevent=enabled
            enable_pattern = r'time=(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*event=enabled'
            match = re.match(enable_pattern, line)
            if match:
                enabled_match = match

    if not enabled_match:
        # Try to get enabled time from extension command execution logs
        print("Agent log does not show extension was enabled", file=sys.stderr)
        sys.exit(1)

    if args.ext_type == "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent":
        enable_time = datetime.strptime(enabled_match.group('timestamp'), u'%Y/%m/%d %H:%M:%S')
    else:
        enable_time = datetime.strptime(enabled_match.group('timestamp'), u'%Y-%m-%dT%H:%M:%SZ')

    start_time = datetime.strptime(args.start_time, u'%Y-%m-%d %H:%M:%S.%f')
    if enable_time < start_time:
        print("Agent log does not show extension was enabled after this test case started. Last enabled time was {0}. This test case started at {1}".format(enable_time, start_time), file=sys.stderr)
        sys.exit(1)
    else:
        print(enable_time)

    sys.exit(0)


if __name__ == "__main__":
    main()
