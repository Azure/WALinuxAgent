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

from __future__ import print_function

import shlex
import subprocess
import sys
import time

SERVICE_RESTART_PATTERN = "service %s restart"
SERVICE_STATUS_PATTERN = "service %s status"
WAAGENT_SERVICE = "waagent"
WALINUXAGENT_SERVICE = "walinuxagent"

MAX_RETRY = 3


def get_agent_name():
    try:
        execute_command(SERVICE_STATUS_PATTERN % WAAGENT_SERVICE)
    except Exception:
        return WALINUXAGENT_SERVICE
    return WAAGENT_SERVICE


def run_and_get_output(cmd):
    ret_code = 1
    retry_count = 0
    # Adding retry logic as machines with Py < 2.7 take longer to restart the agent
    while ret_code != 0 and retry_count < MAX_RETRY:
        try:
            ret_code, output = execute_command(cmd)
        except Exception as e:
            retry_count += 1
            if retry_count == MAX_RETRY:
                raise e
            time.sleep(0.5)  # Sleep for half a sec per retry


def execute_command(cmd):
    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    ret_code = process.poll()
    if ret_code != 0:
        raise Exception("Error while executing command `%s`! Error Code: %s; Output: %s; Error: %s"
                        % (cmd, ret_code, out, err))
    return 0, out


def restart_agent(agent_name):
    run_and_get_output(SERVICE_RESTART_PATTERN % agent_name)


def verify_agent_running(agent_name):
    run_and_get_output(SERVICE_STATUS_PATTERN % agent_name)


def main():
    agent_name = get_agent_name()
    print("Agent Name = " + agent_name)
    restart_agent(agent_name)
    verify_agent_running(agent_name)
    sys.exit(0)


if __name__ == "__main__":
    print("Restarting agent")
    main()
