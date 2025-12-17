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
import datetime
import os
import re
import sys

from assertpy import fail

from azurelinuxagent.common.future import UTC
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import check_log_message, get_agent_memory_quota, using_cgroupv2

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


def skip_if_distro_not_supports_memory_quota():
    if not using_cgroupv2():
        log.info("Skipping  memory quota test as the distro is not using cgroupv2")
        cleanup_test_setup()
        sys.exit(0)


def prepare_agent():
    check_time = datetime.datetime.now(UTC)
    log.info("Executing script update-waagent-conf to enable agent cgroups config flag")
    result = shellutil.run_command(["update-waagent-conf", "Debug.CgroupCheckPeriod=30", "Debug.CgroupLogMetrics=y",
                                    "Debug.CgroupDisableOnProcessCheckFailure=n",
                                    "Debug.CgroupDisableOnQuotaCheckFailure=n",
                                    "Debug.AgentMemoryQuota=104857600"])
    log.info("Successfully enabled agent cgroups config flag: {0}".format(result))

    found: bool = retry_if_false(
        lambda: check_log_message("Agent cgroups enabled: True", after_timestamp=check_time))
    if not found:
        fail("Agent cgroups not enabled")


def verify_agent_has_memory_quota_set():
    """
    This method verifies that the agent's cgroup has memory quota set
    """
    log.info("** Verifying agent cgroup has memory quota set")

    def check_memory_quota() -> bool:
        quota = get_agent_memory_quota()
        if quota is None or quota == "infinity":
            return False
        return True

    found: bool = retry_if_false(check_memory_quota)
    if found:
        log.info("Agent Memory Quota: %s", get_agent_memory_quota())
        log.info("Successfully verified agent cgroup has memory quota set")
    else:
        fail("The agent's cgroup doesn't seem to have memory quota set. Agent Memory Quota: {0}".format(get_agent_memory_quota()))


def verify_agent_reported_memory_metrics():
    """
    This method verifies that the agent reports Memory Usage metrics
    """
    log.info("** Verifying agent reported memory metrics")
    log.info("Parsing agent log for memory metrics")
    memory_usage = []

    def check_agent_log_for_metrics() -> bool:
        for record in AgentLog().read():
            # This regex matches "Memory Usage" with optional (B) and extracts the value
            match = re.search(r"Memory/.*Memory Usage(?: \(B\))?\s*\[walinuxagent\.service\]\s*=\s*([0-9.]+)", record.message)
            if match is not None:
                memory_usage.append(match.group(1))
        if len(memory_usage) < 1:
            return False
        return True

    found: bool = retry_if_false(check_agent_log_for_metrics)
    if found:
        log.info("Memory Usage: %s", memory_usage)
        log.info("Successfully verified agent reported memory usage metrics")
    else:
        fail(
            "The agent doesn't seem to be collecting Memory Usage metrics. Agent found Memory Usage: {0}".format(
                memory_usage))


def verify_memory_throttling_check_on_agent_cgroups():
    """
    This method verifies that the agent detects memory throttling on its cgroup
    """
    log.info("** Verifying agent detected memory throttling on its cgroup")

    throttled_events = []
    pressure_time = []

    def check_agent_log_for_metrics() -> bool:
        for record in AgentLog().read():
            match = re.search(r"Memory/Total Memory Throttled Events \s*\[walinuxagent.service\]\s*=\s*([0-9.]+)", record.message)
            if match is not None:
                throttled_events.append(float(match.group(1)))
            else:
                match = re.search(r"Memory/Memory Pressure \(s\)\s*\[walinuxagent.service\]\s*=\s*([0-9.]+)", record.message)
                if match is not None:
                    pressure_time.append(float(match.group(1)))
        if len(pressure_time) < 1 or len(throttled_events) < 1:
            return False
        return True

    distro = shellutil.run_command("get_distro.py").rstrip().lower()

    if "rhel" in distro:
        log.info("Skipping memory throttling check verification on RHEL distros due to known issues with memory pressure file not present.")
        return

    found: bool = retry_if_false(check_agent_log_for_metrics, delay=60)
    if found:
        log.info("Memory Throttle Events: %s", throttled_events)
        log.info("Memory Pressure Time: %s", pressure_time)
        log.info("Successfully verified agent reported memory throttling metrics")
    else:
        fail(
            "The agent doesn't seem to be collecting Memory Throttling metrics. Agent found Memory Throttle Events: {0} and Pressure: {1}".format(
                throttled_events, pressure_time))


def cleanup_test_setup():
    log.info("Cleaning up test setup")
    drop_in_file = os.path.join(systemd.get_agent_drop_in_path(), "99-ExecStart.conf")
    if os.path.exists(drop_in_file):
        log.info("Removing %s...", drop_in_file)
        os.remove(drop_in_file)
        shellutil.run_command(["systemctl", "daemon-reload"])

    check_time = datetime.datetime.now(UTC)
    shellutil.run_command(["agent-service", "restart"])

    found: bool = retry_if_false(lambda: check_log_message(" Agent cgroups enabled: True", after_timestamp=check_time))
    if not found:
        fail("Agent cgroups not enabled yet")


def main():
    skip_if_distro_not_supports_memory_quota()
    prepare_agent()
    verify_agent_has_memory_quota_set()
    verify_agent_reported_memory_metrics()
    verify_memory_throttling_check_on_agent_cgroups()
    cleanup_test_setup()


run_remote_test(main)
