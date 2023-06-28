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
import logging
import os
import re
import sys

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import BASE_CGROUP, AGENT_CONTROLLERS, get_agent_cgroup_mount_path, \
    AGENT_SERVICE_NAME, exit_if_cgroups_not_supported, print_processes, print_cgroups, \
    verify_agent_cgroup_assigned_correctly


def verify_cgroup_controllers_on_disk():
    logging.info("===== Verifying cgroup controllers exist on disk =====")

    all_controllers_present = os.path.exists(BASE_CGROUP)

    for controller in AGENT_CONTROLLERS:
        controller_path = os.path.join(BASE_CGROUP, controller)
        if not os.path.exists(controller_path):
            logging.info('\tcould not verify controller %s', controller_path)
            all_controllers_present = False
        else:
            logging.info('\tverified controller %s', controller_path)

    if not all_controllers_present:
        raise Exception('Unexpected cgroup controller status!')

    logging.info('\tVerified cgroup controller are present.\n')


def verify_agent_cgroup_created_on_disk():
    logging.info("===== Verifying the agent cgroup paths exist on disk =====")
    agent_cgroup_mount_path = get_agent_cgroup_mount_path()

    logging.info("\texpected agent cgroup mount path: %s", agent_cgroup_mount_path)

    exit_code = 0

    for controller in AGENT_CONTROLLERS:
        agent_controller_path = os.path.join(BASE_CGROUP, controller, agent_cgroup_mount_path[1:])

        if not os.path.exists(agent_controller_path):
            logging.info('\tagent cgroup does not exist on disk in %s', agent_controller_path)
            exit_code += 1
        else:
            logging.info('\tverified agent cgroup %s exists on disk', agent_controller_path)

    if exit_code > 0:
        raise Exception("Agent's cgroup paths couldn't be found on disk.")

    logging.info('\tVerified agent cgroups are present.\n')


def verify_agent_tracking_cgroups():
    logging.info("===== Verifying agent started tracking cgroups from the log =====")

    tracking_agent_cgroup_message_re = r'Started tracking cgroup [^\s]+\s+\[(?P<path>[^\s]+)\]'
    tracked_cgroups = []

    for record in AgentLog().read():
        match = re.search(tracking_agent_cgroup_message_re, record.message)
        if match is not None:
            tracked_cgroups.append(match.group('path'))

    for controller in AGENT_CONTROLLERS:
        if not any(AGENT_SERVICE_NAME in cgroup_path and controller in cgroup_path for cgroup_path in tracked_cgroups):
            raise Exception('Agent {0} is not being tracked. Tracked cgroups:{1}'.format(controller, tracked_cgroups))

    logging.info("\tAgent is tracking cgroups correctly.\n%s", tracked_cgroups)


try:
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.DEBUG, stream=sys.stdout)
    exit_if_cgroups_not_supported()

    print_processes()
    print_cgroups()

    verify_cgroup_controllers_on_disk()
    verify_agent_cgroup_created_on_disk()

    verify_agent_cgroup_assigned_correctly()
    verify_agent_tracking_cgroups()

    sys.exit(0)

except Exception as e:
    print(f"{e}", file=sys.stderr)
    sys.exit(1)
