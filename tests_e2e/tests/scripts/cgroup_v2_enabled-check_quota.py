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
# Script verifies that no cpu quota in the agent cgroup

from assertpy import fail, assert_that

from tests_e2e.tests.lib.cgroup_helpers import check_agent_quota_disabled, get_agent_cpu_quota, check_log_message
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def main():
    """
    Verifies that no cpu quota in the agent cgroup
    """
    log.info("Querying the agent CPU quota")
    disabled: bool = retry_if_false(check_agent_quota_disabled)
    if not disabled:
        fail("The agent failed to disable its CPUQuota when cgroups were not enabled. Current CPUQuota: {0}".format(get_agent_cpu_quota()))
    log.info("The agent cgroup CPU quota is not set as expected")

    #
    # 2025-04-18T21:15:37.336480Z INFO ExtHandler ExtHandler [CGI] Setting azuremonitoragent's CPUQuota to 25%
    log.info("Parsing agent log to look for CPU quota set messages")
    found: bool = check_log_message("INFO ExtHandler.*Setting.*CPUQuota")
    assert_that(found).described_as("The agent log should not contain matching records of cpu quota being set").is_false()
    log.info("The agent log indicates that agent does not enforce limits in cgroupv2 distros")

if __name__ == "__main__":
    main()