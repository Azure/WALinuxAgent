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
from tests_e2e.tests.lib.cgroup_helpers import check_agent_quota_disabled, check_log_message
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def restart_ext_handler():
    log.info("Restarting the extension handler")
    shellutil.run_command(["pkill", "-f", "WALinuxAgent.*run-exthandler"])


def verify_agent_cgroups_not_enabled():
    """
    Verifies that the agent cgroups not enabled when ama extension(unexpected) processes are found in the agent cgroup
    """
    log.info("Verifying agent cgroups are not enabled")

    ama_process_found: bool = retry_if_false(lambda: check_log_message("The agent's cgroup includes unexpected processes:.+/var/lib/waagent/Microsoft.Azure.Monitor"))
    if not ama_process_found:
        fail("Agent failed to found ama extension processes in the agent cgroup")

    found: bool = retry_if_false(lambda: check_log_message("Found unexpected processes in the agent cgroup before agent enable cgroups"))
    if not found:
        fail("Agent failed to found unknown processes in the agent cgroup")

    disabled: bool = retry_if_false(check_agent_quota_disabled)
    if not disabled:
        fail("The agent failed to disable its CPUQuota when cgroups were not enabled")


def main():
    restart_ext_handler()
    verify_agent_cgroups_not_enabled()


if __name__ == "__main__":
    main()
