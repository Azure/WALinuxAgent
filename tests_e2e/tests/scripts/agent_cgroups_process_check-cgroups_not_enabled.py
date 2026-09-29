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

# This script verifies agent detected unexpected processes in the agent cgroup before cgroup initialization

from assertpy import fail

from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.cgroup_helpers import check_agent_quota_disabled, check_log_message, get_agent_cpu_quota
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def restart_ext_handler():
    log.info("Restarting the extension handler")
    shellutil.run_command(["pkill", "-f", "(WALinuxAgent|waagent).*run-exthandler"])


def verify_agent_cgroups_not_enabled():
    """
    Verifies that the agent cgroups are not enabled when (unexpected) processes
    are found in the agent cgroup.
    """
    log.info("Verifying agent cgroups are not enabled")

    dummy_pid = None
    try:
        # The dummy PID is the PID of the long-running `sleep` process spawned by the CustomScript
        # extension in the previous test step (see agent_cgroups_process_check._install_cse_with_dummy_process).
        # CSE's commandToExecute launches a detached shell that execs `sleep 100000` (so the shell's
        # PID becomes the sleep PID) and writes it to this file before CSE itself exits quickly.
        # This leftover process lands in the agent cgroup, and we look it up here to verify that
        # the agent detected it as an unexpected process and refused to re-enable cgroups.
        with open("/var/lib/waagent/tmp/dummy_proc.pid") as fh:
            dummy_pid = fh.read().strip()
    except Exception as e:
        fail("Could not read process PID file: {0}".format(e))

    dummy_process_found: bool = retry_if_false(lambda: check_log_message(
        "The agent's cgroup includes unexpected processes:.+PID: {0}".format(dummy_pid)))
    if not dummy_process_found:
        fail("Agent failed to find dummy extension-spawned process (pid={0}) in the agent cgroup".format(dummy_pid))

    found: bool = retry_if_false(lambda: check_log_message("Found unexpected processes in the agent cgroup before agent enable cgroups"))
    if not found:
        fail("Agent failed to find unknown processes in the agent cgroup")

    disabled: bool = retry_if_false(check_agent_quota_disabled)
    if not disabled:
        fail("The agent failed to disable its CPUQuota when cgroups were not enabled. Current CPUQuota: {0}".format(get_agent_cpu_quota()))


def main():
    restart_ext_handler()
    verify_agent_cgroups_not_enabled()


if __name__ == "__main__":
    main()
