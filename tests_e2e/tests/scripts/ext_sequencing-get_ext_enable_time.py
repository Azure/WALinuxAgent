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
    args, _ = parser.parse_known_args()

    # Extension enabled time is in extension CommandExecution.log
    command_exec_log_path = Path('/var/log/azure/' + args.ext_type + '/CommandExecution.log')
    command_exec_log = open(command_exec_log_path, 'r')
    for line in command_exec_log.readlines():
        line = line.rstrip()
        if args.ext_type == "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent":
            # AMA logs enable succeeded and its timestamp to the agent log:
            # 2023/09/26 04:07:33 [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.28.5] Enable,success,0,Enable succeeded
            enable_pattern = r'.*(?P<timestamp>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[Microsoft\.Azure\.Monitor\.AzureMonitorLinuxAgent\-.*] .*Enable succeeded.*'
            enable_match = re.match(enable_pattern, line)
            if enable_match:
                print(datetime.strptime(enable_match.group('timestamp'), u'%Y/%m/%d %H:%M:%S'))
                sys.exit(0)
        else:
            # For RC and CSE, we can determine when enable succeeded from the stdout of the enable command execution from
            # the agent log:
            # 2023-09-26T04:07:39.042948Z INFO ExtHandler [Microsoft.CPlat.Core.RunCommandLinux-1.0.5] Command: bin/run-command-shim enable
            # [stdout]
            # ...
            # time=2023-09-26T04:07:37Z version=v1.0.4/git@b3be41d-dirty operation=enable seq=0 event=enabledevent=enabled
            enable_pattern = r'time=(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*event=enabled'
            enable_match = re.match(enable_pattern, line)
            if enable_match:
                print(datetime.strptime(enable_match.group('timestamp'), u'%Y-%m-%dT%H:%M:%SZ'))
                sys.exit(0)

    # Try to get enabled time from extension command execution logs
    print("Agent log does not show extension was enabled")
    sys.exit(1)


if __name__ == "__main__":
    main()
