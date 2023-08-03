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

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import verify_if_distro_supports_cgroup, \
    verify_agent_cgroup_assigned_correctly, BASE_CGROUP, EXT_CONTROLLERS, get_unit_cgroup_mount_path, \
    GATESTEXT_SERVICE, AZUREMONITORAGENT_SERVICE, MDSD_SERVICE, check_agent_quota_disabled, \
    check_cgroup_disabled_with_unknown_process, CGROUP_TRACKED_PATTERN, AZUREMONITOREXT_FULL_NAME, GATESTEXT_FULL_NAME, \
    print_cgroups
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test


def verify_custom_script_cgroup_assigned_correctly():
    """
    This method verifies that the CSE script is created expected folder after install and also checks if CSE ran under the expected cgroups
    """
    log.info("===== Verifying custom script was assigned to the correct cgroups")

    # CSE creates this folder to save the output of cgroup information where the CSE script was executed. Since CSE process exits after execution,
    # and cgroup paths gets cleaned up by the system, so this information saved at run time when the extension executed.
    check_temporary_folder_exists()

    cpu_mounted = False
    memory_mounted = False

    log.info("custom script cgroup mounts:")

    with open('/var/lib/waagent/tmp/custom_script_check') as fh:
        controllers = fh.read()
        log.info("%s", controllers)

        extension_path = "/azure.slice/azure-vmextensions.slice/azure-vmextensions-Microsoft.Azure.Extensions.CustomScript"

        correct_cpu_mount_v1 = "cpu,cpuacct:{0}".format(extension_path)
        correct_cpu_mount_v2 = "cpuacct,cpu:{0}".format(extension_path)

        correct_memory_mount = "memory:{0}".format(extension_path)

        for mounted_controller in controllers.split("\n"):
            if correct_cpu_mount_v1 in mounted_controller or correct_cpu_mount_v2 in mounted_controller:
                log.info('Custom script extension mounted under correct cgroup '
                      'for CPU: %s', mounted_controller)
                cpu_mounted = True
            elif correct_memory_mount in mounted_controller:
                log.info('Custom script extension mounted under correct cgroup '
                      'for Memory: %s', mounted_controller)
                memory_mounted = True

        if not cpu_mounted:
            fail('Custom script not mounted correctly for CPU! Expected {0} or {1}'.format(correct_cpu_mount_v1, correct_cpu_mount_v2))

        if not memory_mounted:
            fail('Custom script not mounted correctly for Memory! Expected {0}'.format(correct_memory_mount))


def check_temporary_folder_exists():
    tmp_folder = "/var/lib/waagent/tmp"
    if not os.path.exists(tmp_folder):
        fail("Temporary folder {0} was not created which means CSE script did not run!".format(tmp_folder))


def verify_ext_cgroup_controllers_created_on_file_system():
    """
    This method ensure that extension cgroup controllers are created on file system after extension install
    """
    log.info("===== Verifying ext cgroup controllers exist on file system")

    all_controllers_present = os.path.exists(BASE_CGROUP)
    missing_controllers_path = []
    verified_controllers_path = []

    for controller in EXT_CONTROLLERS:
        controller_path = os.path.join(BASE_CGROUP, controller)
        if not os.path.exists(controller_path):
            all_controllers_present = False
            missing_controllers_path.append(controller_path)
        else:
            verified_controllers_path.append(controller_path)

    if not all_controllers_present:
        fail('Expected all of the extension controller: {0} paths present in the file system after extension install. But missing cgroups paths are :{1}\n'
             'and verified cgroup paths are: {2} \nSystem mounted cgroups are \n{3}'.format(EXT_CONTROLLERS, missing_controllers_path, verified_controllers_path, print_cgroups()))

    log.info('Verified all extension cgroup controller paths are present and they are: \n {0}'.format(verified_controllers_path))


def verify_extension_service_cgroup_created_on_file_system():
    """
    This method ensure that extension service cgroup paths are created on file system after running extension
    """
    log.info("===== Verifying the extension service cgroup paths exist on file system")

    # GA Test Extension Service
    gatestext_cgroup_mount_path = get_unit_cgroup_mount_path(GATESTEXT_SERVICE)
    verify_extension_service_cgroup_created(GATESTEXT_SERVICE, gatestext_cgroup_mount_path)

    # Azure Monitor Extension Service
    azuremonitoragent_cgroup_mount_path = get_unit_cgroup_mount_path(AZUREMONITORAGENT_SERVICE)
    azuremonitoragent_service_name = AZUREMONITORAGENT_SERVICE
    # Old versions of AMA extension has different service name
    if azuremonitoragent_cgroup_mount_path is None:
        azuremonitoragent_cgroup_mount_path = get_unit_cgroup_mount_path(MDSD_SERVICE)
        azuremonitoragent_service_name = MDSD_SERVICE
    verify_extension_service_cgroup_created(azuremonitoragent_service_name, azuremonitoragent_cgroup_mount_path)

    log.info('Verified all extension service cgroup paths created in file system .\n')


def verify_extension_service_cgroup_created(service_name, cgroup_mount_path):
    log.info("expected extension service cgroup mount path: %s", cgroup_mount_path)

    all_controllers_present = True
    missing_cgroups_path = []
    verified_cgroups_path = []

    for controller in EXT_CONTROLLERS:
        # cgroup_mount_path is similar to /azure.slice/walinuxagent.service
        # cgroup_mount_path[1:] = azure.slice/walinuxagent.service
        # expected extension_service_controller_path similar to /sys/fs/cgroup/cpu/azure.slice/walinuxagent.service
        extension_service_controller_path = os.path.join(BASE_CGROUP, controller, cgroup_mount_path[1:])

        if not os.path.exists(extension_service_controller_path):
            all_controllers_present = False
            missing_cgroups_path.append(extension_service_controller_path)
        else:
            verified_cgroups_path.append(extension_service_controller_path)

    if not all_controllers_present:
        fail("Extension service: [{0}] cgroup paths couldn't be found on file system. Missing cgroup paths are: {1} \n Verified cgroup paths are: {2} \n "
             "System mounted cgroups are \n{3}".format(service_name, missing_cgroups_path, verified_cgroups_path, print_cgroups()))


def verify_ext_cgroups_tracked():
    """
    Checks if ext cgroups are tracked by the agent. This is verified by checking the agent log for the message "Started tracking cgroup {extension_name}"
    """
    log.info("===== Verifying ext cgroups tracked")

    cgroups_added_for_telemetry = []
    gatestext_cgroups_tracked = False
    azuremonitoragent_cgroups_tracked = False
    gatestext_service_cgroups_tracked = False
    azuremonitoragent_service_cgroups_tracked = False

    for record in AgentLog().read():

        # Cgroup tracking logged as
        # 2021-11-14T13:09:59.351961Z INFO ExtHandler ExtHandler Started tracking cgroup Microsoft.Azure.Extensions.Edp.GATestExtGo-1.0.0.2
        # [/sys/fs/cgroup/cpu,cpuacct/azure.slice/azure-vmextensions.slice/azure-vmextensions-Microsoft.Azure.Extensions.Edp.GATestExtGo_1.0.0.2.slice]
        cgroup_tracked_match = CGROUP_TRACKED_PATTERN.findall(record.message)
        if len(cgroup_tracked_match) != 0:
            name, path = cgroup_tracked_match[0][0], cgroup_tracked_match[0][1]
            if name.startswith(GATESTEXT_FULL_NAME):
                gatestext_cgroups_tracked = True
            elif name.startswith(AZUREMONITOREXT_FULL_NAME):
                azuremonitoragent_cgroups_tracked = True
            elif name.startswith(GATESTEXT_SERVICE):
                gatestext_service_cgroups_tracked = True
            elif name.startswith(AZUREMONITORAGENT_SERVICE) or name.startswith(MDSD_SERVICE):
                azuremonitoragent_service_cgroups_tracked = True
            cgroups_added_for_telemetry.append((name, path))

    # agent, gatest extension, azuremonitor extension and extension service cgroups
    if len(cgroups_added_for_telemetry) < 1:
        fail('Expected cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0} and found \n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not gatestext_cgroups_tracked:
        fail('Expected gatestext cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0} and found \n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not azuremonitoragent_cgroups_tracked:
        fail('Expected azuremonitoragent cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0} and found \n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not gatestext_service_cgroups_tracked:
        fail('Expected gatestext service cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0} and found \n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not azuremonitoragent_service_cgroups_tracked:
        fail('Expected azuremonitoragent service cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0} and found \n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    log.info("Extension cgroups tracked as expected\n%s", cgroups_added_for_telemetry)


def main():
    verify_if_distro_supports_cgroup()
    verify_ext_cgroup_controllers_created_on_file_system()
    verify_custom_script_cgroup_assigned_correctly()
    verify_agent_cgroup_assigned_correctly()
    verify_extension_service_cgroup_created_on_file_system()
    verify_ext_cgroups_tracked()


try:
    run_remote_test(main)
except Exception as e:
    # It is possible that  agent cgroup can be disabled due to UNKNOWN process or throttled before we run this check, in that case, we should ignore the validation
    if check_agent_quota_disabled() and check_cgroup_disabled_with_unknown_process():
        log.info("Cgroup is disabled due to UNKNOWN process, ignoring ext cgroups validations")
    else:
        raise
