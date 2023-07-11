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
import sys

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import exit_if_cgroups_not_supported, \
    verify_agent_cgroup_assigned_correctly, BASE_CGROUP, EXT_CONTROLLERS, get_unit_cgroup_mount_path, \
    GATESTEXT_SERVICE, AZUREMONITORAGENT_SERVICE, MDSD_SERVICE, check_quota_disabled, \
    check_cgroup_disabled_with_unknown_process, CGROUP_TRACKED_PATTERN, AZUREMONITOREXT_FULL_NAME, GATESTEXT_FULL_NAME, \
    print_cgroups


def verify_custom_script_cgroup_assigned_correctly():
    # This method verifies that the CSE script is created expected folder after install and also checks if CSE ran under the expected cgroups
    logging.info("===== Verifying custom script was assigned to the correct cgroups =====")

    # CSE creates this folder to save the output of cgroup information where the CSE script was executed. This inoformation saved at run time since when the extension executed(process exits),
    # the cgroup paths gets cleaned up by the system.
    check_temporary_folder_exists()

    cpu_mounted = False

    logging.info("\tcustom script cgroup mounts:")

    with open('/var/lib/waagent/tmp/custom_script_check') as fh:
        controllers = fh.read()
        logging.info("%s", controllers)

        extension_path = "/azure.slice/azure-vmextensions.slice/azure-vmextensions-Microsoft.Azure.Extensions.CustomScript"

        correct_cpu_mount_v1 = "cpu,cpuacct:{0}".format(extension_path)
        correct_cpu_mount_v2 = "cpuacct,cpu:{0}".format(extension_path)

        for mounted_controller in controllers.split("\n"):
            if correct_cpu_mount_v1 in mounted_controller or correct_cpu_mount_v2 in mounted_controller:
                logging.info('\tCustom script extension mounted under correct cgroup '
                      'for CPU: %s', mounted_controller)
                cpu_mounted = True

        if not cpu_mounted:
            raise Exception('Custom script not mounted correctly! Expected {0} or {1}'.format(correct_cpu_mount_v1, correct_cpu_mount_v2))

    logging.info("")


def verify_agent_cgroup_assigned_correctly_after_ama_install():
    # This method adds the debug info of system processes that were captured while installing AMA and also make sure that the agent is running under the expected cgroups afrer AMA install
    logging.info("===== Verifying the agent cgroup consists only of agent processes after installing AMA =====")
    with open('/var/lib/waagent/tmp/ps_check_after_ama') as fh:
        lines = fh.readlines()
        for process in lines:
            logging.info(process)
        logging.info("\n")

    verify_agent_cgroup_assigned_correctly()


def check_temporary_folder_exists():
    tmp_folder = "/var/lib/waagent/tmp"
    if not os.path.exists(tmp_folder):
        raise Exception("Temporary folder {0} was not created which means CSE script did not run!".format(tmp_folder))


def verify_ext_cgroup_controllers_created_on_disk():
    # This method ensure that extension cgroup controllers are created on disk after extension install
    logging.info("===== Verifying ext cgroup controllers exist on disk =====")

    all_controllers_present = os.path.exists(BASE_CGROUP)

    for controller in EXT_CONTROLLERS:
        controller_path = os.path.join(BASE_CGROUP, controller)
        if not os.path.exists(controller_path):
            logging.warning('\tcould not verify controller %s', controller_path)
            all_controllers_present = False
        else:
            logging.info('\tverified controller %s', controller_path)

    if not all_controllers_present:
        raise Exception('Not all of the ext controllers {0} present on disk. System mounted cgroups are \n{1}'.format(EXT_CONTROLLERS, print_cgroups()))

    logging.info('\tVerified extension cgroup controller are present.\n')


def verify_extension_service_cgroup_created_on_disk():
    # This method ensure that extension service cgroup paths are created on disk after running extension
    logging.info("===== Verifying the extension service cgroup paths exist on disk =====")

    # GA Test Extension Service
    gatestext_cgroup_mount_path = get_unit_cgroup_mount_path(GATESTEXT_SERVICE)
    verify_extension_service_cgroup_created(gatestext_cgroup_mount_path)

    # Azure Monitor Extension Service
    azuremonitoragent_cgroup_mount_path = get_unit_cgroup_mount_path(AZUREMONITORAGENT_SERVICE)
    if azuremonitoragent_cgroup_mount_path is None:
        azuremonitoragent_cgroup_mount_path = get_unit_cgroup_mount_path(MDSD_SERVICE)
    verify_extension_service_cgroup_created(azuremonitoragent_cgroup_mount_path)

    logging.info('\tFound the extension service cgroup paths in disk .\n')


def verify_extension_service_cgroup_created(cgroup_mount_path):
    logging.info("\texpected extension service cgroup mount path: %s", cgroup_mount_path)

    all_controllers_present = True

    for controller in EXT_CONTROLLERS:
        # cgroup_mount_path is similar to /azure.slice/walinuxagent.service
        # cgroup_mount_path[1:] = azure.slice/walinuxagent.service
        # expected extension_service_controller_path similar to /sys/fs/cgroup/cpu/azure.slice/walinuxagent.service
        extension_service_controller_path = os.path.join(BASE_CGROUP, controller, cgroup_mount_path[1:])

        if not os.path.exists(extension_service_controller_path):
            logging.warning('\textension service cgroup does not exist on disk in %s', extension_service_controller_path)
            all_controllers_present = False
        else:
            logging.info('\tverified extension service cgroup %s exists on disk', extension_service_controller_path)

    if not all_controllers_present:
        raise Exception("Extension service's cgroup paths couldn't be found on disk. System mounted cgroups are \n{0}".format(print_cgroups()))


def verify_ext_cgroups_tracked():
    # Checks if ext cgroups are tracked by the agent. This is verified by checking the agent log for the message "Started tracking cgroup {extension_name}"
    logging.info("===== Verifying ext cgroups tracked =====")

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
        raise Exception('Expected cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0}\n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not gatestext_cgroups_tracked:
        raise Exception('Expected gatestext cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0}\n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not azuremonitoragent_cgroups_tracked:
        raise Exception('Expected azuremonitoragent cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0}\n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not gatestext_service_cgroups_tracked:
        raise Exception('Expected gatestext service cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0}\n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    if not azuremonitoragent_service_cgroups_tracked:
        raise Exception('Expected azuremonitoragent service cgroups were not tracked, according to the agent log. '
                        'Pattern searched for: {0}\n{1}'.format(CGROUP_TRACKED_PATTERN.pattern, cgroups_added_for_telemetry))

    logging.info("\tExtension cgroups tracked as expected\n%s", cgroups_added_for_telemetry)


try:
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.DEBUG, stream=sys.stdout)
    exit_if_cgroups_not_supported()

    verify_ext_cgroup_controllers_created_on_disk()
    verify_custom_script_cgroup_assigned_correctly()
    verify_agent_cgroup_assigned_correctly_after_ama_install()
    verify_extension_service_cgroup_created_on_disk()
    verify_ext_cgroups_tracked()

    sys.exit(0)

except Exception as e:
    # It is possible that  agent cgroup can be disabled due to UNKNOWN process or throttled before we run this check, in that case, we should ignore the validation
    if check_quota_disabled() and check_cgroup_disabled_with_unknown_process():
        logging.info("Cgroup is disabled due to UNKNOWN process, ignoring ext cgroups validations")
    else:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)
