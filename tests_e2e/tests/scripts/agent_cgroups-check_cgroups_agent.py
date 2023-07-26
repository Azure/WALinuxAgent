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
import os
import re
import sys
import traceback

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import BASE_CGROUP, AGENT_CONTROLLERS, get_agent_cgroup_mount_path, \
    AGENT_SERVICE_NAME, verify_if_distro_supports_cgroup, print_cgroups, \
    verify_agent_cgroup_assigned_correctly
from tests_e2e.tests.lib.logging import log


def verify_mounted_cgroup_controllers():
    """
    Checks if Agent controllers CPU, Memory are mounted in the system
    """
    log.info("===== Verifying cgroup controllers are mounted in the system =====")

    all_controllers_present = os.path.exists(BASE_CGROUP)

    for controller in AGENT_CONTROLLERS:
        controller_path = os.path.join(BASE_CGROUP, controller)
        if not os.path.exists(controller_path):
            log.warning('\tcould not verify controller %s', controller_path)
            all_controllers_present = False
        else:
            log.info('\tverified controller %s', controller_path)

    if not all_controllers_present:
        raise Exception('Not all of the controllers {0} mounted in expected cgroups. System mounted cgroups are:\n{1}'.format(AGENT_CONTROLLERS, print_cgroups()))

    log.info('\tVerified cgroup controller are present.\n')


def verify_agent_cgroup_created_on_file_system():
    """
    Checks agent service is running in azure.slice/{agent_service) cgroup and mounted in same system cgroup controllers mounted path
    """
    log.info("===== Verifying the agent cgroup paths exist on disk =====")
    agent_cgroup_mount_path = get_agent_cgroup_mount_path()
    all_agent_cgroup_controllers_present = True

    log.info("\texpected agent cgroup mount path: %s", agent_cgroup_mount_path)

    for controller in AGENT_CONTROLLERS:
        agent_controller_path = os.path.join(BASE_CGROUP, controller, agent_cgroup_mount_path[1:])

        if not os.path.exists(agent_controller_path):
            log.warning('\tagent cgroup does not exist on disk in %s', agent_controller_path)
            all_agent_cgroup_controllers_present = False
        else:
            log.info('\tverified agent cgroup %s exists on disk', agent_controller_path)

    if not all_agent_cgroup_controllers_present:
        raise Exception("Agent's cgroup paths couldn't be found on disk.")

    log.info('\tVerified agent cgroups are present.\n')


def verify_agent_cgroups_tracked():
    """
    Checks if agent is tracking agent cgroups path for polling resource usage. This is verified by checking the agent log for the message "Started tracking cgroup"
    """
    log.info("===== Verifying agent started tracking cgroups from the log =====")

    tracking_agent_cgroup_message_re = r'Started tracking cgroup [^\s]+\s+\[(?P<path>[^\s]+)\]'
    tracked_cgroups = []

    for record in AgentLog().read():
        match = re.search(tracking_agent_cgroup_message_re, record.message)
        if match is not None:
            tracked_cgroups.append(match.group('path'))

    for controller in AGENT_CONTROLLERS:
        if not any(AGENT_SERVICE_NAME in cgroup_path and controller in cgroup_path for cgroup_path in tracked_cgroups):
            raise Exception('Agent {0} is not being tracked. Tracked cgroups:{1}'.format(controller, tracked_cgroups))

    log.info("\tAgent is tracking cgroups correctly.\n%s", tracked_cgroups)


try:
    verify_if_distro_supports_cgroup()

    verify_mounted_cgroup_controllers()
    verify_agent_cgroup_created_on_file_system()

    verify_agent_cgroup_assigned_correctly()
    verify_agent_cgroups_tracked()

    sys.exit(0)

except Exception as e:
    log.error("%s:\n%s", e, traceback.format_exc())
    sys.exit(1)
