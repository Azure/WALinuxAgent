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
import shutil
import time

from assertpy import fail

from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.ga.cgroupconfigurator import _DROP_IN_FILE_CPU_QUOTA
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import check_agent_quota_disabled, \
    get_agent_cpu_quota
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


def prepare_agent():
    # This function prepares the agent:
    #    1) It modifies the service unit file to wrap the agent process with a script that starts the actual agent and then
    #       launches an instance of the dummy process to consume the CPU. Since all these processes are in the same cgroup,
    #       this has the same effect as the agent itself consuming the CPU.
    #
    #       The process tree is similar to
    #
    #           /usr/bin/python3 /home/azureuser/bin/agent_cpu_quota-start_service.py /usr/bin/python3 -u /usr/sbin/waagent -daemon
    #             ├─/usr/bin/python3 -u /usr/sbin/waagent -daemon
    #             │   └─python3 -u bin/WALinuxAgent-9.9.9.9-py3.8.egg -run-exthandlers
    #             │       └─4*[{python3}]
    #             ├─dd if=/dev/zero of=/dev/null
    #             │
    #             └─{python3}
    #
    #       And the agent's cgroup looks like
    #
    #       CGroup: /azure.slice/walinuxagent.service
    #              ├─10507 /usr/bin/python3 /home/azureuser/bin/agent_cpu_quota-start_service.py /usr/bin/python3 -u /usr/sbin/waagent -daemon
    #              ├─10508 /usr/bin/python3 -u /usr/sbin/waagent -daemon
    #              ├─10516 python3 -u bin/WALinuxAgent-9.9.9.9-py3.8.egg -run-exthandlers
    #              ├─10711 dd if=/dev/zero of=/dev/null
    #
    #    2) It turns on a few debug flags and resart the agent
    log.info("***Preparing agent for testing cpu quota")
    #
    # Create a drop in file to wrap "start-service.py" around the actual agent: This will ovveride the ExecStart line in the agent's unit file
    #
    #     ExecStart= (need to be empty to clear the original ExecStart)
    #     ExecStart=/home/.../agent_cgroups-start-service.py /usr/bin/python3 -u /usr/sbin/waagent -daemon
    #
    service_file = systemd.get_agent_unit_file()
    exec_start = None
    with open(service_file, "r") as file_:
        for line in file_:
            match = re.match("ExecStart=(.+)", line)
            if match is not None:
                exec_start = match.group(1)
                break
        else:
            file_.seek(0)
            raise Exception("Could not find ExecStart in {0}\n:{1}".format(service_file, file_.read()))
    agent_python = exec_start.split()[0]
    current_directory = os.path.dirname(os.path.abspath(__file__))
    start_service_script = os.path.join(current_directory, "agent_cpu_quota-start_service.py")
    drop_in_file = os.path.join(systemd.get_agent_drop_in_path(), "99-ExecStart.conf")
    log.info("Creating %s...", drop_in_file)
    with open(drop_in_file, "w") as file_:
        file_.write("""
[Service]
ExecStart=
ExecStart={0} {1} {2}
""".format(agent_python, start_service_script, exec_start))
    log.info("Executing daemon-reload")
    shellutil.run_command(["systemctl", "daemon-reload"])

    # Disable all checks on cgroups and enable log metrics every 20 sec
    log.info("Executing script update-waagent-conf to enable agent cgroups config flag")
    result = shellutil.run_command(["update-waagent-conf", "Debug.CgroupCheckPeriod=20", "Debug.CgroupLogMetrics=y",
                           "Debug.CgroupDisableOnProcessCheckFailure=n", "Debug.CgroupDisableOnQuotaCheckFailure=n"])
    log.info("Successfully enabled agent cgroups config flag: {0}".format(result))


def verify_agent_reported_metrics():
    """
    This method verifies that the agent reports % Processor Time and Throttled Time metrics
    """
    log.info("** Verifying agent reported metrics")
    log.info("Parsing agent log for metrics")
    processor_time = []
    throttled_time = []

    def check_agent_log_for_metrics() -> bool:
        for record in AgentLog().read():
            match = re.search(r"% Processor Time\s*\[walinuxagent.service\]\s*=\s*([0-9.]+)", record.message)
            if match is not None:
                processor_time.append(float(match.group(1)))
            else:
                match = re.search(r"Throttled Time\s*\[walinuxagent.service\]\s*=\s*([0-9.]+)", record.message)
                if match is not None:
                    throttled_time.append(float(match.group(1)))
        if len(processor_time) < 1 or len(throttled_time) < 1:
            return False
        return True

    found: bool = retry_if_false(check_agent_log_for_metrics)
    if found:
        log.info("%% Processor Time: %s", processor_time)
        log.info("Throttled Time: %s", throttled_time)
        log.info("Successfully verified agent reported resource metrics")
    else:
        fail(
            "The agent doesn't seem to be collecting % Processor Time and Throttled Time metrics. Agent found Processor Time: {0}, Throttled Time: {1}".format(
                processor_time, throttled_time))


def wait_for_log_message(message, timeout=datetime.timedelta(minutes=5)):
    log.info("Checking agent's log for message matching [%s]", message)
    start_time = datetime.datetime.now()
    while datetime.datetime.now() - start_time <= timeout:
        for record in AgentLog().read():
            match = re.search(message, record.message, flags=re.DOTALL)
            if match is not None:
                log.info("Found message:\n\t%s", record.text.replace("\n", "\n\t"))
                return
        time.sleep(30)
    fail("The agent did not find [{0}] in its log within the allowed timeout".format(message))


def verify_process_check_on_agent_cgroups():
    """
    This method checks agent detect unexpected processes in its cgroup and disables the CPUQuota
    """
    log.info("***Verifying process check on  agent cgroups")
    log.info("Ensuring agent CPUQuota is enabled and backup the drop-in file to restore later in further tests")
    if check_agent_quota_disabled():
        fail("The agent's CPUQuota is not enabled: {0}".format(get_agent_cpu_quota()))
    quota_drop_in = os.path.join(systemd.get_agent_drop_in_path(), _DROP_IN_FILE_CPU_QUOTA)
    quota_drop_in_backup = quota_drop_in + ".bk"
    log.info("Backing up %s to %s...", quota_drop_in, quota_drop_in_backup)
    shutil.copy(quota_drop_in, quota_drop_in_backup)
    #
    # Re-enable Process checks on cgroups and verify that the agent detects unexpected processes in its cgroup and disables the CPUQuota wehen
    # that happens
    #
    shellutil.run_command(["update-waagent-conf", "Debug.CgroupDisableOnProcessCheckFailure=y"])

    # The log message indicating the check failed is similar to
    #     2021-03-29T23:33:15.603530Z INFO MonitorHandler ExtHandler Disabling resource usage monitoring. Reason: Check on cgroups failed:
    #     [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 25826] python3\x00/home/nam/Compute-Runtime-Tux-Pipeline/dungeon_crawler/s']
    wait_for_log_message(
        "Disabling resource usage monitoring. Reason: Check on cgroups failed:.+The agent's cgroup includes unexpected processes")
    disabled: bool = retry_if_false(lambda: check_agent_quota_disabled())
    if not disabled:
        fail("The agent did not disable its CPUQuota: {0}".format(get_agent_cpu_quota()))


def verify_throttling_time_check_on_agent_cgroups():
    """
    This method checks agent disables its CPUQuota when it exceeds its throttling limit
    """
    log.info("***Verifying CPU throttling check on  agent cgroups")
    # Now disable the check on unexpected processes and enable the check on throttledtime and verify that the agent disables its CPUQuota when it exceeds its throttling limit
    log.info("Re-enabling CPUQuota...")
    quota_drop_in = os.path.join(systemd.get_agent_drop_in_path(), _DROP_IN_FILE_CPU_QUOTA)
    quota_drop_in_backup = quota_drop_in + ".bk"
    log.info("Restoring %s from %s...", quota_drop_in, quota_drop_in_backup)
    shutil.copy(quota_drop_in_backup, quota_drop_in)
    shellutil.run_command(["systemctl", "daemon-reload"])
    shellutil.run_command(["update-waagent-conf", "Debug.CgroupDisableOnProcessCheckFailure=n", "Debug.CgroupDisableOnQuotaCheckFailure=y", "Debug.AgentCpuThrottledTimeThreshold=5"])

    # The log message indicating the check failed is similar to
    #     2021-04-01T20:47:55.892569Z INFO MonitorHandler ExtHandler Disabling resource usage monitoring. Reason: Check on cgroups failed:
    #     [CGroupsException] The agent has been throttled for 121.339916938 seconds
    #
    # After we need to wait for a little longer for the agent to update systemd:
    #     2021-04-14T01:51:44.399860Z INFO MonitorHandler ExtHandler Executing systemctl daemon-reload...
    #
    wait_for_log_message(
        "Disabling resource usage monitoring. Reason: Check on cgroups failed:.+The agent has been throttled",
        timeout=datetime.timedelta(minutes=10))
    wait_for_log_message("Stopped tracking cgroup walinuxagent.service", timeout=datetime.timedelta(minutes=10))
    wait_for_log_message("Executing systemctl daemon-reload...", timeout=datetime.timedelta(minutes=5))
    disabled: bool = retry_if_false(lambda: check_agent_quota_disabled())
    if not disabled:
        fail("The agent did not disable its CPUQuota: {0}".format(get_agent_cpu_quota()))


def main():
    prepare_agent()
    verify_agent_reported_metrics()
    verify_process_check_on_agent_cgroups()
    verify_throttling_time_check_on_agent_cgroups()


run_remote_test(main)
