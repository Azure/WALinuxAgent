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

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import BASE_CGROUP, AGENT_CONTROLLERS, get_agent_cgroup_mount_path, \
    AGENT_SERVICE_NAME, verify_if_distro_supports_cgroup, print_cgroups, \
    verify_agent_cgroup_assigned_correctly
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test


def verify_if_cgroup_controllers_are_mounted():
    """
    Checks if controllers CPU, Memory that agent use are mounted in the system
    """
    log.info("===== Verifying cgroup controllers that agent use are mounted in the system")

    all_controllers_present = os.path.exists(BASE_CGROUP)
    missing_controllers = []
    mounted_controllers = []

    for controller in AGENT_CONTROLLERS:
        controller_path = os.path.join(BASE_CGROUP, controller)
        if not os.path.exists(controller_path):
            all_controllers_present = False
            missing_controllers.append(controller_path)
        else:
            mounted_controllers.append(controller_path)

    if not all_controllers_present:
        fail('Not all of the controllers {0} mounted in expected cgroups. Mounted controllers are: {1}.\n '
             'Missing controllers are: {2} \n System mounted cgroups are:\n{3}'.format(AGENT_CONTROLLERS, mounted_controllers, missing_controllers, print_cgroups()))

    log.info('Verified all cgroup controllers are present.\n {0}'.format(mounted_controllers))


def verify_agent_cgroup_created_on_file_system():
    """
    Checks agent service is running in azure.slice/{agent_service) cgroup and mounted in same system cgroup controllers mounted path
    """
    log.info("===== Verifying the agent cgroup paths exist on file system")
    agent_cgroup_mount_path = get_agent_cgroup_mount_path()
    all_agent_cgroup_controllers_path_exist = True
    missing_agent_cgroup_controllers_path = []
    verified_agent_cgroup_controllers_path = []

    log.info("expected agent cgroup mount path: %s", agent_cgroup_mount_path)

    for controller in AGENT_CONTROLLERS:
        agent_controller_path = os.path.join(BASE_CGROUP, controller, agent_cgroup_mount_path[1:])

        if not os.path.exists(agent_controller_path):
            all_agent_cgroup_controllers_path_exist = False
            missing_agent_cgroup_controllers_path.append(agent_controller_path)
        else:
            verified_agent_cgroup_controllers_path.append(agent_controller_path)

    if not all_agent_cgroup_controllers_path_exist:
        fail("Agent's cgroup paths couldn't be found on file system. Missing agent cgroups path :{0}.\n Verified agent cgroups path:{1}".format(missing_agent_cgroup_controllers_path, verified_agent_cgroup_controllers_path))

    log.info('Verified all agent cgroup paths are present.\n {0}'.format(verified_agent_cgroup_controllers_path))


def verify_agent_cgroups_tracked():
    """
    Checks if agent is tracking agent cgroups path for polling resource usage. This is verified by checking the agent log for the message "Started tracking cgroup"
    """
    log.info("===== Verifying agent started tracking cgroups from the log")

    tracking_agent_cgroup_message_re = r'Started tracking cgroup [^\s]+\s+\[(?P<path>[^\s]+)\]'
    tracked_cgroups = []

    for record in AgentLog().read():
        match = re.search(tracking_agent_cgroup_message_re, record.message)
        if match is not None:
            tracked_cgroups.append(match.group('path'))

    for controller in AGENT_CONTROLLERS:
        if not any(AGENT_SERVICE_NAME in cgroup_path and controller in cgroup_path for cgroup_path in tracked_cgroups):
            fail('Agent {0} is not being tracked. Tracked cgroups:{1}'.format(controller, tracked_cgroups))

    log.info("Agent is tracking cgroups correctly.\n%s", tracked_cgroups)


def main():
    verify_if_distro_supports_cgroup()

    verify_if_cgroup_controllers_are_mounted()
    verify_agent_cgroup_created_on_file_system()

    verify_agent_cgroup_assigned_correctly()
    verify_agent_cgroups_tracked()


run_remote_test(main)
