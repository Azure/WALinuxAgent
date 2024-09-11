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
# Requires Python 2.6+ and Openssl 1.0+

import errno
import os
import re

from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.cgroupcontroller import _CgroupController, MetricValue, MetricsCategory, MetricsCounter

re_v1_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')
re_v2_usage_time = re.compile(r'[\s\S]*usage_usec (\d+)[\s\S]*')


class _CpuController(_CgroupController):
    def __init__(self, name, cgroup_path):
        super(_CpuController, self).__init__(name, cgroup_path)

        self._osutil = get_osutil()
        self._previous_cgroup_cpu = None
        self._previous_system_cpu = None
        self._current_cgroup_cpu = None
        self._current_system_cpu = None
        self._previous_throttled_time = None
        self._current_throttled_time = None

    def _get_cpu_stat_counter(self, counter_name):
        """
        Gets the value for the provided counter in cpu.stat
        """
        try:
            with open(os.path.join(self.path, 'cpu.stat')) as cpu_stat:
                #
                # Sample file v1:
                #   # cat cpu.stat
                #   nr_periods  51660
                #   nr_throttled 19461
                #   throttled_time 1529590856339
                #
                # Sample file v2
                #   # cat cpu.stat
                #   usage_usec 200161503
                #   user_usec 199388368
                #   system_usec 773134
                #   core_sched.force_idle_usec 0
                #   nr_periods 40059
                #   nr_throttled 40022
                #   throttled_usec 3565247992
                #   nr_bursts 0
                #   burst_usec 0
                #
                for line in cpu_stat:
                    match = re.match(r'{0}\s+(\d+)'.format(counter_name), line)
                    if match is not None:
                        return int(match.groups()[0])
                raise Exception("Cannot find {0}".format(counter_name))
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                return 0
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))

    def _cpu_usage_initialized(self):
        """
        Returns True if cpu usage has been initialized, False otherwise.
        """
        return self._current_cgroup_cpu is not None and self._current_system_cpu is not None

    def initialize_cpu_usage(self):
        """
        Sets the initial values of CPU usage. This function must be invoked before calling get_cpu_usage().
        """
        raise NotImplementedError()

    def get_cpu_usage(self):
        """
        Computes the CPU used by the cgroup since the last call to this function.

        The usage is measured as a percentage of utilization of 1 core in the system. For example,
        using 1 core all of the time on a 4-core system would be reported as 100%.

        NOTE: initialize_cpu_usage() must be invoked before calling get_cpu_usage()
        """
        raise NotImplementedError()

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        """
        Computes the throttled time (in seconds) since the last call to this function.
        NOTE: initialize_cpu_usage() must be invoked before calling this function
        Compute only current throttled time if read_previous_throttled_time set to False
        """
        raise NotImplementedError()

    def get_tracked_metrics(self, **kwargs):
        # Note: If the current cpu usage is less than the previous usage (metric is negative), then an empty array will
        # be returned and the agent won't track the metrics.
        tracked = []
        cpu_usage = self.get_cpu_usage()
        if cpu_usage >= float(0):
            tracked.append(MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.PROCESSOR_PERCENT_TIME, self.name, cpu_usage))

        if 'track_throttled_time' in kwargs and kwargs['track_throttled_time']:
            throttled_time = self.get_cpu_throttled_time()
            if cpu_usage >= float(0) and throttled_time >= float(0):
                tracked.append(MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.THROTTLED_TIME, self.name, throttled_time))

        return tracked

    def get_unit_properties(self):
        return ["CPUAccounting", "CPUQuotaPerSecUSec"]


class CpuControllerV1(_CpuController):
    def initialize_cpu_usage(self):
        if self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() should be invoked only once")
        self._current_cgroup_cpu = self._get_cpu_ticks(allow_no_such_file_or_directory_error=True)
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._current_throttled_time = self._get_cpu_stat_counter(counter_name='throttled_time')

    def _get_cpu_ticks(self, allow_no_such_file_or_directory_error=False):
        """
        Returns the number of USER_HZ of CPU time (user and system) consumed by this cgroup.

        If allow_no_such_file_or_directory_error is set to True and cpuacct.stat does not exist the function
        returns 0; this is useful when the function can be called before the cgroup has been created.
        """
        try:
            cpuacct_stat = self._get_file_contents('cpuacct.stat')
        except Exception as e:
            if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:  # pylint: disable=E1101
                raise CGroupsException("Failed to read cpuacct.stat: {0}".format(ustr(e)))
            if not allow_no_such_file_or_directory_error:
                raise e
            cpuacct_stat = None

        cpu_ticks = 0

        if cpuacct_stat is not None:
            #
            # Sample file:
            #     # cat /sys/fs/cgroup/cpuacct/azure.slice/walinuxagent.service/cpuacct.stat
            #     user 10190
            #     system 3160
            #
            match = re_v1_user_system_times.match(cpuacct_stat)
            if not match:
                raise CGroupsException("The contents of {0} are invalid: {1}".format(self._get_cgroup_file('cpuacct.stat'), cpuacct_stat))
            cpu_ticks = int(match.groups()[0]) + int(match.groups()[1])

        return cpu_ticks

    def get_cpu_usage(self):
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_usage()")

        self._previous_cgroup_cpu = self._current_cgroup_cpu
        self._previous_system_cpu = self._current_system_cpu
        self._current_cgroup_cpu = self._get_cpu_ticks()
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()

        cgroup_delta = self._current_cgroup_cpu - self._previous_cgroup_cpu
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(100.0 * self._osutil.get_processor_cores() * float(cgroup_delta) / float(system_delta), 3)

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        # Throttled time is reported in nanoseconds in v1
        if not read_previous_throttled_time:
            return float(self._get_cpu_stat_counter(counter_name='throttled_time') / 1E9)

        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_throttled_time()")

        self._previous_throttled_time = self._current_throttled_time
        self._current_throttled_time = self._get_cpu_stat_counter(counter_name='throttled_time')

        return round(float(self._current_throttled_time - self._previous_throttled_time) / 1E9, 3)


class CpuControllerV2(_CpuController):
    @staticmethod
    def get_system_uptime():
        """
        Get the uptime of the system (including time spent in suspend) in seconds.
        /proc/uptime contains two numbers (values in seconds): the uptime of the system (including time spent in
        suspend) and the amount of time spent in the idle process:
            # cat /proc/uptime
            365380.48 722644.81

        :return: System uptime in seconds
        :rtype: float
        """
        uptime_contents = fileutil.read_file('/proc/uptime').split()
        return float(uptime_contents[0])

    def _get_system_usage(self):
        try:
            return self.get_system_uptime()
        except (OSError, IOError) as e:
            raise CGroupsException("Couldn't read /proc/uptime: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Couldn't parse /proc/uptime: {0}".format(ustr(e)))

    def initialize_cpu_usage(self):
        if self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() should be invoked only once")
        self._current_cgroup_cpu = self._get_cpu_time(allow_no_such_file_or_directory_error=True)
        self._current_system_cpu = self._get_system_usage()
        self._current_throttled_time = self._get_cpu_stat_counter(counter_name='throttled_usec')

    def _get_cpu_time(self, allow_no_such_file_or_directory_error=False):
        """
        Returns the CPU time (user and system) consumed by this cgroup in seconds.

        If allow_no_such_file_or_directory_error is set to True and cpu.stat does not exist the function
        returns 0; this is useful when the function can be called before the cgroup has been created.
        """
        try:
            cpu_stat = self._get_file_contents('cpu.stat')
        except Exception as e:
            if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:  # pylint: disable=E1101
                raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
            if not allow_no_such_file_or_directory_error:
                raise e
            cpu_stat = None

        cpu_time = 0

        if cpu_stat is not None:
            #
            # Sample file:
            #     # cat /sys/fs/cgroup/azure.slice/azure-walinuxagent.slice/azure-walinuxagent-logcollector.slice/collect-logs.scope/cpu.stat
            #     usage_usec 1990707
            #     user_usec 1939858
            #     system_usec 50848
            #     core_sched.force_idle_usec 0
            #     nr_periods 397
            #     nr_throttled 397
            #     throttled_usec 37994949
            #     nr_bursts 0
            #     burst_usec 0
            #
            match = re_v2_usage_time.match(cpu_stat)
            if not match:
                raise CGroupsException("The contents of {0} are invalid: {1}".format(self._get_cgroup_file('cpu.stat'), cpu_stat))
            cpu_time = int(match.groups()[0]) / 1E6

        return cpu_time

    def get_cpu_usage(self):
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_usage()")

        self._previous_cgroup_cpu = self._current_cgroup_cpu
        self._previous_system_cpu = self._current_system_cpu
        self._current_cgroup_cpu = self._get_cpu_time()
        self._current_system_cpu = self._get_system_usage()

        cgroup_delta = self._current_cgroup_cpu - self._previous_cgroup_cpu
        system_delta = max(1.0, self._current_system_cpu - self._previous_system_cpu)

        return round(100.0 * float(cgroup_delta) / float(system_delta), 3)

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        # Throttled time is reported in microseconds in v2
        if not read_previous_throttled_time:
            return float(self._get_cpu_stat_counter(counter_name='throttled_usec') / 1E6)

        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_throttled_time()")

        self._previous_throttled_time = self._current_throttled_time
        self._current_throttled_time = self._get_cpu_stat_counter(counter_name='throttled_usec')

        return round(float(self._current_throttled_time - self._previous_throttled_time) / 1E6, 3)
