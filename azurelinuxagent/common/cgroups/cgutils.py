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

WRAPPER_CGROUP_NAME = "WALinuxAgent"
METRIC_HIERARCHIES = ['cpu', 'memory']
MEMORY_DEFAULT = -1

# percentage of a single core

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
