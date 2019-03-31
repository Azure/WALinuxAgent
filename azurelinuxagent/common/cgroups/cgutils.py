# Copyright 2019 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+

import re

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.osutil.default import BASE_CGROUPS

WRAPPER_CGROUP_NAME = "WALinuxAgent"
AGENT_CGROUP_NAME = "WALinuxAgent"
METRIC_HIERARCHIES = ['cpu', 'memory']
MEMORY_DEFAULT = -1

# percentage of a single core
DEFAULT_CPU_LIMIT_AGENT = 10
DEFAULT_CPU_LIMIT_EXT = 40

DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN = 256  # mb, applies to agent and extensions
DEFAULT_MEM_LIMIT_MAX_MB_FOR_AGENT = 512  # mb, applies to agent only
DEFAULT_MEM_LIMIT_PCT_FOR_EXTN = 15  # percent, applies to extensions

re_user_system_times = re.compile('user (\d+)\nsystem (\d+)\n')


class CGroupsException(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class Cpu(object):
    def __init__(self, cgt):
        """
        Initialize data collection for the Cpu hierarchy. User must call update() before attempting to get
        any useful metrics.

        :param cgt: CGroupsTelemetry
        :return:
        """
        self.cgt = cgt
        self.osutil = get_osutil()
        self.current_cpu_total = self.get_current_cpu_total()
        self._previous_cpu_total = 0
        self.current_system_cpu = self.osutil.get_total_cpu_ticks_since_boot()
        self._previous_system_cpu = 0

    def __str__(self):
        return "Cgroup: Current {0}, previous {1}; System: Current {2}, previous {3}".format(
            self.current_cpu_total, self._previous_cpu_total, self.current_system_cpu, self._previous_system_cpu
        )

    def get_current_cpu_total(self):
        """
        Compute the number of USER_HZ of CPU time (user and system) consumed by this cgroup since boot.

        :return: int
        """
        cpu_total = 0
        try:
            cpu_stat = self.cgt.cgroup. \
                get_file_contents('cpu', 'cpuacct.stat')
            if cpu_stat is not None:
                m = re_user_system_times.match(cpu_stat)
                if m:
                    cpu_total = int(m.groups()[0]) + int(m.groups()[1])
        except CGroupsException:
            # There are valid reasons for file contents to be unavailable; for example, if an extension
            # has not yet started (or has stopped) an associated service on a VM using systemd, the cgroup for
            # the service will not exist ('cause systemd will tear it down). This might be a transient or a
            # long-lived state, so there's no point in logging it, much less emitting telemetry.
            pass
        return cpu_total

    def update(self):
        """
        Update all raw data required to compute metrics of interest. The intent is to call update() once, then
        call the various get_*() methods which use this data, which we've collected exactly once.
        """
        self._previous_cpu_total = self.current_cpu_total
        self._previous_system_cpu = self.current_system_cpu
        self.current_cpu_total = self.get_current_cpu_total()
        self.current_system_cpu = self.osutil.get_total_cpu_ticks_since_boot()

    def get_cpu_percent(self):
        """
        Compute the percent CPU time used by this cgroup over the elapsed time since the last time this instance was
        update()ed.  If the cgroup fully consumed 2 cores on a 4 core system, return 200.

        :return: CPU usage in percent of a single core
        :rtype: float
        """
        cpu_delta = self.current_cpu_total - self._previous_cpu_total
        system_delta = max(1, self.current_system_cpu - self._previous_system_cpu)

        return round(float(cpu_delta * self.cgt.cpu_count * 100) / float(system_delta), 3)

    def collect(self):
        """
        Collect and return a list of all cpu metrics. If no metrics are collected, return an empty list.

        :rtype: [(str, str, float)]
        [("Process", "% Processor Time", usage)]
        """
        self.update()
        usage = self.get_cpu_percent()
        return [("Process", "% Processor Time", usage)]


class Memory(object):
    def __init__(self, cgt):
        """
        Initialize data collection for the Memory hierarchy

        :param CGroupsTelemetry cgt: The telemetry object for which memory metrics should be collected
        :return:
        """
        self.cgt = cgt

    def get_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = self.cgt.cgroup.get_parameter('memory', 'memory.usage_in_bytes')
        if not usage:
            usage = "0"
        return int(usage)

    def collect(self):
        """
        Collect and return a list of all memory metrics

        :rtype: [(str, str, float)]
        """
        usage = self.get_memory_usage()
        return [("Memory", "Total Memory Usage", usage)]


class CGroupsLimits(object):
    def __init__(self, cgroup_name, resource_configuration=None):
        self.osutil = get_osutil()

        if not cgroup_name or cgroup_name == "":
            cgroup_name = "Agents+Extensions"

        self.cpu_limit = self.get_cpu_limits(cgroup_name, resource_configuration,
                                             CGroupsLimits.get_default_cpu_limits)
        self.memory_limit = self.get_memory_limits(cgroup_name, resource_configuration,
                                                   CGroupsLimits.get_default_memory_limits)
        self.memory_flags = self.get_memory_flags(cgroup_name, resource_configuration,
                                                  CGroupsLimits.get_default_memory_flags)

    def get_cpu_limits(self, name, resource_configuration, compute_default):
        limit_requested = None

        cpu_limits_requested_by_extn = resource_configuration.get_cpu_limits_for_extension() if resource_configuration \
            else None

        if cpu_limits_requested_by_extn:
            cores_count = self.osutil.get_processor_cores()
            # Sorted by cores. -1 is the default entry - and the first entry.
            # Sorted inside azurelinuxagent.ga.exthandlers.CpuLimits

            default_limits = cpu_limits_requested_by_extn.cpu_limits[0]
            if len(cpu_limits_requested_by_extn.cpu_limits) > 1:
                for i in cpu_limits_requested_by_extn.cpu_limits[1:]:
                    if cores_count <= i.cores:
                        limit_requested = i.limit_percentage
                        break

            if not limit_requested:
                limit_requested = default_limits.limit_percentage

        return limit_requested if limit_requested else compute_default(name)

    def get_memory_limits(self, name, resource_configuration, compute_default):
        limit_requested = None

        memory_limits_requested_by_extn = resource_configuration.get_memory_limits_for_extension() if \
            resource_configuration else None

        if memory_limits_requested_by_extn:
            total_memory = self.osutil.get_total_mem()
            limit_requested = max(DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN,
                                  min((memory_limits_requested_by_extn.max_limit_percentage / 100.0) * total_memory,
                                       memory_limits_requested_by_extn.max_limit_MBs)
                                  )

        return limit_requested if limit_requested else compute_default(name)

    def get_memory_flags(self, cgroup_name, resource_configuration, get_default_memory_flags):
        flags_requested = {}

        memory_limits_requested_by_extn = resource_configuration.get_memory_limits_for_extension() if \
            resource_configuration else None

        if memory_limits_requested_by_extn:
            if memory_limits_requested_by_extn.memory_pressure_warning:
                flags_requested["memory_pressure_warning"] = memory_limits_requested_by_extn.memory_pressure_warning
            else:
                flags_requested["memory_pressure_warning"] = get_default_memory_flags()["memory_pressure_warning"]

            if memory_limits_requested_by_extn.memory_oom_kill:
                flags_requested["memory_oom_kill"] = memory_limits_requested_by_extn.memory_oom_kill
            else:
                flags_requested["memory_oom_kill"] = get_default_memory_flags()["memory_oom_kill"]

        return flags_requested

    @staticmethod
    def get_default_cpu_limits(cgroup_name):
        # default values
        cpu_limit = DEFAULT_CPU_LIMIT_EXT
        if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
            cpu_limit = DEFAULT_CPU_LIMIT_AGENT
        return cpu_limit

    @staticmethod
    def get_default_memory_limits(cgroup_name):
        os_util = get_osutil()

        # default values
        mem_limit = max(DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN, round(os_util.get_total_mem() * DEFAULT_MEM_LIMIT_PCT_FOR_EXTN / 100, 0))

        # agent values
        if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
            mem_limit = min(DEFAULT_MEM_LIMIT_MAX_MB_FOR_AGENT, mem_limit)
        return mem_limit

    @staticmethod
    def get_default_memory_flags():
        default_memory_flags = {"memory_pressure_warning": None, "memory_oom_kill": "disabled"}
        return default_memory_flags
