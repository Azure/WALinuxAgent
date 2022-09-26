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
from collections import namedtuple

import errno
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil

AGENT_NAME_TELEMETRY = "walinuxagent.service"  # Name used for telemetry; it needs to be consistent even if the name of the service changes

MetricValue = namedtuple('Metric', ['category', 'counter', 'instance', 'value'])


class MetricsCategory(object):
    MEMORY_CATEGORY = "Memory"
    CPU_CATEGORY = "CPU"


class MetricsCounter(object):
    PROCESSOR_PERCENT_TIME = "% Processor Time"
    TOTAL_MEM_USAGE = "Total Memory Usage"
    MAX_MEM_USAGE = "Max Memory Usage"
    THROTTLED_TIME = "Throttled Time"


re_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')


class CGroup(object):
    def __init__(self, name, cgroup_path):
        """
        Initialize _data collection for the Memory controller
        :param: name: Name of the CGroup
        :param: cgroup_path: Path of the controller
        :return:
        """
        self.name = name
        self.path = cgroup_path

    def __str__(self):
        return "{0} [{1}]".format(self.name, self.path)

    def _get_cgroup_file(self, file_name):
        return os.path.join(self.path, file_name)

    def _get_file_contents(self, file_name):
        """
        Retrieve the contents to file.

        :param str file_name: Name of file within that metric controller
        :return: Entire contents of the file
        :rtype: str
        """
        parameter_file = self._get_cgroup_file(file_name)

        return fileutil.read_file(parameter_file)

    def _get_parameters(self, parameter_name, first_line_only=False):
        """
        Retrieve the values of a parameter from a controller.
        Returns a list of values in the file.

        :param first_line_only: return only the first line.
        :param str parameter_name: Name of file within that metric controller
        :return: The first line of the file, without line terminator
        :rtype: [str]
        """
        result = []
        try:
            values = self._get_file_contents(parameter_name).splitlines()
            result = values[0] if first_line_only else values
        except IndexError:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("File {0} is empty but should not be".format(parameter_filename))
            raise CGroupsException("File {0} is empty but should not be".format(parameter_filename))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise e
            parameter_filename = self._get_cgroup_file(parameter_name)
            raise CGroupsException("Exception while attempting to read {0}".format(parameter_filename), e)
        return result

    def is_active(self):
        try:
            tasks = self._get_parameters("tasks")
            if tasks:
                return len(tasks) != 0
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # only suppressing file not found exceptions.
                pass
            else:
                logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                     'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                     ' Internal error: {1}'.format(self.path, ustr(e)))
        except CGroupsException as e:
            logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                 'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                 ' Internal error: {1}'.format(self.path, ustr(e)))
        return False

    def get_tracked_metrics(self, **_):
        """
        Retrieves the current value of the metrics tracked for this cgroup and returns them as an array.

        Note: Agent won't track the metrics if the current cpu ticks less than previous value and returns empty array.
        """
        raise NotImplementedError()


class CpuCgroup(CGroup):
    def __init__(self, name, cgroup_path):
        super(CpuCgroup, self).__init__(name, cgroup_path)

        self._osutil = get_osutil()
        self._previous_cgroup_cpu = None
        self._previous_system_cpu = None
        self._current_cgroup_cpu = None
        self._current_system_cpu = None
        self._previous_throttled_time = None
        self._current_throttled_time = None

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
            match = re_user_system_times.match(cpuacct_stat)
            if not match:
                raise CGroupsException("The contents of {0} are invalid: {1}".format(self._get_cgroup_file('cpuacct.stat'), cpuacct_stat))
            cpu_ticks = int(match.groups()[0]) + int(match.groups()[1])

        return cpu_ticks

    def _get_throttled_time(self):
        try:
            with open(os.path.join(self.path, 'cpu.stat')) as cpu_stat:
                #
                # Sample file:
                #
                #   # cat /sys/fs/cgroup/cpuacct/azure.slice/walinuxagent.service/cpu.stat
                #   nr_periods  51660
                #   nr_throttled 19461
                #   throttled_time 1529590856339
                #
                for line in cpu_stat:
                    match = re.match(r'throttled_time\s+(\d+)', line)
                    if match is not None:
                        return int(match.groups()[0])
                raise Exception("Cannot find throttled_time")
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                return 0
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))

    def _cpu_usage_initialized(self):
        return self._current_cgroup_cpu is not None and self._current_system_cpu is not None

    def initialize_cpu_usage(self):
        """
        Sets the initial values of CPU usage. This function must be invoked before calling get_cpu_usage().
        """
        if self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() should be invoked only once")
        self._current_cgroup_cpu = self._get_cpu_ticks(allow_no_such_file_or_directory_error=True)
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._current_throttled_time = self._get_throttled_time()

    def get_cpu_usage(self):
        """
        Computes the CPU used by the cgroup since the last call to this function.

        The usage is measured as a percentage of utilization of 1 core in the system. For example,
        using 1 core all of the time on a 4-core system would be reported as 100%.

        NOTE: initialize_cpu_usage() must be invoked before calling get_cpu_usage()
        """
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_usage()")

        self._previous_cgroup_cpu = self._current_cgroup_cpu
        self._previous_system_cpu = self._current_system_cpu
        self._current_cgroup_cpu = self._get_cpu_ticks()
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()

        cgroup_delta = self._current_cgroup_cpu - self._previous_cgroup_cpu
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(100.0 * self._osutil.get_processor_cores() * float(cgroup_delta) / float(system_delta), 3)

    def get_throttled_time(self):
        """
        Computes the throttled time (in seconds) since the last call to this function.
        NOTE: initialize_cpu_usage() must be invoked before calling this function
        """
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_throttled_time()")

        self._previous_throttled_time = self._current_throttled_time
        self._current_throttled_time = self._get_throttled_time()

        return float(self._current_throttled_time - self._previous_throttled_time) / 1E9

    def get_tracked_metrics(self, **kwargs):
        tracked = []
        cpu_usage = self.get_cpu_usage()
        if cpu_usage >= float(0):
            tracked.append(MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.PROCESSOR_PERCENT_TIME, self.name, cpu_usage))

        if 'track_throttled_time' in kwargs and kwargs['track_throttled_time']:
            throttled_time = self.get_throttled_time()
            if cpu_usage >= float(0) and throttled_time >= float(0):
                tracked.append(MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.THROTTLED_TIME, self.name, throttled_time))

        return tracked


class MemoryCgroup(CGroup):
    def get_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = None
        try:
            usage = self._get_parameters('memory.usage_in_bytes', first_line_only=True)
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.usage_in_bytes"), e)

        return int(usage)

    def get_max_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = None
        try:
            usage = self._get_parameters('memory.max_usage_in_bytes', first_line_only=True)
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.usage_in_bytes"), e)

        return int(usage)

    def get_tracked_metrics(self, **_):
        return [
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_MEM_USAGE, self.name, self.get_memory_usage()),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MAX_MEM_USAGE, self.name, self.get_max_memory_usage()),
        ]
