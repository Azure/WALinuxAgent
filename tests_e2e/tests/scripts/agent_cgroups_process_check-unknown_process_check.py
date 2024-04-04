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

# This script forces the process check by putting unknown process in the agent's cgroup

import os
import subprocess
import datetime

from assertpy import fail

from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.cgroup_helpers import check_agent_quota_disabled, check_log_message, get_unit_cgroup_paths, AGENT_SERVICE_NAME
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def prepare_agent():
    check_time = datetime.datetime.utcnow()
    log.info("Executing script update-waagent-conf to enable agent cgroups config flag")
    result = shellutil.run_command(["update-waagent-conf", "Debug.CgroupCheckPeriod=20", "Debug.CgroupLogMetrics=y",
                                    "Debug.CgroupDisableOnProcessCheckFailure=y",
                                    "Debug.CgroupDisableOnQuotaCheckFailure=n"])
    log.info("Successfully enabled agent cgroups config flag: {0}".format(result))

    found: bool = retry_if_false(lambda: check_log_message(" Agent cgroups enabled: True", after_timestamp=check_time))
    if not found:
        fail("Agent cgroups not enabled")


def creating_dummy_process():
    log.info("Creating dummy process to add to agent's cgroup")
    dd_command = ["sleep", "60m"]
    proc = subprocess.Popen(dd_command)
    return proc.pid


def remove_dummy_process(pid):
    log.info("Removing dummy process from agent's cgroup")
    shellutil.run_command(["kill", "-9", str(pid)])


def disable_agent_cgroups_with_unknown_process(pid):
    """
    Adding dummy process to the agent's cgroup and verifying that the agent detects the unknown process and disables cgroups

    Note: System may kick the added process out of the cgroups, keeps adding until agent detect that process
    """

    def unknown_process_found(cpu_cgroup):
        cgroup_procs_path = os.path.join(cpu_cgroup, "cgroup.procs")
        log.info("Adding dummy process %s to cgroup.procs file %s", pid, cgroup_procs_path)
        try:
            with open(cgroup_procs_path, 'a') as f:
                f.write("\n")
                f.write(str(pid))
        except Exception as e:
            log.warning("Error while adding process to cgroup.procs file: {0}".format(e))
            return False

        # The log message indicating the check failed is similar to
        #     2021-03-29T23:33:15.603530Z INFO MonitorHandler ExtHandler Disabling resource usage monitoring. Reason: Check on cgroups failed:
        #     [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 25826] python3\x00/home/nam/Compute-Runtime-Tux-Pipeline/dungeon_crawler/s']
        found: bool = retry_if_false(lambda: check_log_message(
            "Disabling resource usage monitoring. Reason: Check on cgroups failed:.+The agent's cgroup includes unexpected processes:.+{0}".format(
                pid)), attempts=3)
        return found and retry_if_false(check_agent_quota_disabled, attempts=3)

    cpu_cgroup, _ = get_unit_cgroup_paths(AGENT_SERVICE_NAME)

    found: bool = retry_if_false(lambda: unknown_process_found(cpu_cgroup), attempts=3)
    if not found:
        fail("The agent did not detect unknown process: {0}".format(pid))


def main():
    prepare_agent()
    pid = creating_dummy_process()
    disable_agent_cgroups_with_unknown_process(pid)
    remove_dummy_process(pid)


if __name__ == "__main__":
    main()
