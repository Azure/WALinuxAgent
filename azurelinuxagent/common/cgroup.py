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
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil

re_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')

# The metric classes (Cpu, Memory, etc) can all assume that CGroups is enabled, as the CGroupTelemetry
# class is very careful not to call them if CGroups isn't enabled. Any tests should be disabled if the osutil
# is_cgroups_support() method returns false.


class CGroup(object):
    def __init__(self, extension_name, cgroup_path, controller_type):
        self.name = extension_name
        self.path = cgroup_path
        self.controller = controller_type

    def _get_cgroup_file(self, file_name):
        return os.path.join(self.path, file_name)

    def get_file_contents(self, controller, file_name):
        """
        Retrieve the value of a parameter from a controller.

        :param str controller: Name of cgroup metric controller
        :param str file_name: Name of file within that metric controller
        :return: Entire contents of the file
        :rtype: str
        """
        if controller == self.controller:
            parameter_file = self._get_cgroup_file(file_name)

            try:
                return fileutil.read_file(parameter_file)
            except Exception:
                raise CGroupsException("Could not retrieve cgroup file {0}/{1}".format(self.path, file_name))
        else:
            raise CGroupsException("Incorrect controller: {0} passed for cgroup: {1}. Cgroup path is: {2}".format(
                controller, self.name, self.path))

    def get_parameter(self, controller, parameter_name):
        """
        Retrieve the value of a parameter from a hierarchy.
        Assumes the parameter is the sole line of the file.

        :param str controller: Name of cgroup metric hierarchy
        :param str parameter_name: Name of file within that metric hierarchy
        :return: The first line of the file, without line terminator
        :rtype: str
        """
        result = ""
        try:
            values = self.get_file_contents(controller, parameter_name).splitlines()
            result = values[0]
        except IndexError:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("File {0} is empty but should not be".format(parameter_filename))
        except CGroupsException:
            # ignore if the file does not exist yet
            pass
        except Exception as e:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("Exception while attempting to read {0}: {1}".format(parameter_filename, ustr(e)))
        return result

    def get_parameters(self, controller, parameter_name):
        """
        Retrieve the value of a parameter from a hierarchy.
        Returns a list of values in the file.

        :param str controller: Name of cgroup metric hierarchy
        :param str parameter_name: Name of file within that metric hierarchy
        :return: The first line of the file, without line terminator
        :rtype: [str]
        """
        result = []
        try:
            result = self.get_file_contents(controller, parameter_name).splitlines()
        except IndexError:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("File {0} is empty but should not be".format(parameter_filename))
        except CGroupsException:
            # ignore if the file does not exist yet
            pass
        except Exception as e:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("Exception while attempting to read {0}: {1}".format(parameter_filename, ustr(e)))
        return result

    def collect(self):
        raise NotImplementedError()

    def is_active(self):
        tasks = self.get_parameters(self.controller, "tasks")
        return len(tasks) != 0


class CpuCgroup(CGroup):
    def __init__(self, extension_name, cgroup_path, controller="cpu"):
        """
        Initialize data collection for the Cpu hierarchy. User must call update() before attempting to get
        any useful metrics.

        :param path: Filepath
        :return:
        """
        super(CpuCgroup, self).__init__(extension_name, cgroup_path, controller)

        self._osutil = get_osutil()
        self._current_cpu_total = self._get_current_cpu_total()
        self._previous_cpu_total = 0
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._previous_system_cpu = 0

    def __str__(self):
        return "Cgroup: Current {0}, previous {1}; System: Current {2}, previous {3}".format(
            self._current_cpu_total, self._previous_cpu_total, self._current_system_cpu, self._previous_system_cpu
        )

    def _get_current_cpu_total(self):
        """
        Compute the number of USER_HZ of CPU time (user and system) consumed by this cgroup since boot.

        :return: int
        """
        cpu_total = 0
        try:
            cpu_stat = self.get_file_contents('cpu', 'cpuacct.stat')
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

    def _update_cpu_data(self):
        """
        Update all raw data required to compute metrics of interest. The intent is to call update() once, then
        call the various get_*() methods which use this data, which we've collected exactly once.
        """
        self._previous_cpu_total = self._current_cpu_total
        self._previous_system_cpu = self._current_system_cpu
        self._current_cpu_total = self._get_current_cpu_total()
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()

    def _get_cpu_percent(self):
        """
        Compute the percent CPU time used by this cgroup over the elapsed time since the last time this instance was
        update()ed.  If the cgroup fully consumed 2 cores on a 4 core system, return 200.

        :return: CPU usage in percent of a single core
        :rtype: float
        """
        cpu_delta = self._current_cpu_total - self._previous_cpu_total
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(float(cpu_delta * self.cgt.cpu_count * 100) / float(system_delta), 3)

    def collect(self):
        """
        Collect and return a list of all cpu metrics. If no metrics are collected, return an empty list.

        :rtype: [(str, str, float)]
        """
        self._update_cpu_data()
        usage = self._get_cpu_percent()
        return [CollectedMetrics("cpu", "% Processor Time", usage)]


class MemoryCgroup(CGroup):
    def __init__(self, extension_name, cgroup_path, controller="memory"):
        """
        Initialize data collection for the Memory hierarchy

        :param CGroupsTelemetry cgt: The telemetry object for which memory metrics should be collected
        :return:
        """
        super(MemoryCgroup, self).__init__(extension_name, cgroup_path, controller)

    def _get_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = self.get_parameter('memory', 'memory.usage_in_bytes')
        if not usage:
            usage = "0"
        return int(usage)

    def _get_memory_max_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = self.get_parameter(self.controller, 'memory.max_usage_in_bytes')
        if not usage:
            usage = "0"
        return int(usage)

    def collect(self):
        """
        Collect and return a list of all memory metrics

        :rtype: [(str, str, float)]
        """
        usage = self._get_memory_usage()
        max_usage = self._get_memory_max_usage()
        return [CollectedMetrics("memory", "Total Memory Usage", usage), CollectedMetrics("memory", "Max Memory Usage", max_usage)]


class CollectedMetrics(object):
    def __init__(self, controller, metric_name, value):
        self.controller = controller
        self.metric_name = metric_name
        self.value = value

#
# TODO: Do we need this code?
#
#
# MEMORY_DEFAULT = -1
#
# # percentage of a single core
# DEFAULT_CPU_LIMIT_AGENT = 10
# DEFAULT_CPU_LIMIT_EXT = 40
#
# DEFAULT_MEM_LIMIT_MIN_MB = 256  # mb, applies to agent and extensions
# DEFAULT_MEM_LIMIT_MAX_MB = 512  # mb, applies to agent only
# DEFAULT_MEM_LIMIT_PCT = 15  # percent, applies to extensions
#
# @staticmethod
# def _convert_cpu_limit_to_fraction(value):
#     """
#     Convert a CPU limit from percent (e.g. 50 meaning 50%) to a decimal fraction (0.50).
#     :return: Fraction of one CPU to be made available (e.g. 0.5 means half a core)
#     :rtype: float
#     """
#     try:
#         limit = float(value)
#     except ValueError:
#         raise CGroupsException('CPU Limit must be convertible to a float')
#
#     if limit <= float(0) or limit > float(CGroupConfigurator.get_num_cores() * 100):
#         raise CGroupsException('CPU Limit must be between 0 and 100 * numCores')
#
#     return limit / 100.0
# def set_cpu_limit(self, limit=None):
#     """
#     Limit this cgroup to a percentage of a single core. limit=10 means 10% of one core; 150 means 150%, which
#     is useful only in multi-core systems.
#     To limit a cgroup to utilize 10% of a single CPU, use the following commands:
#         # echo 10000 > /cgroup/cpu/red/cpu.cfs_quota_us
#         # echo 100000 > /cgroup/cpu/red/cpu.cfs_period_us
#
#     :param limit:
#     """
#     if not CGroupConfigurator.enabled():
#         return
#
#     if limit is None:
#         return
#
#     if 'cpu' in self.cgroups:
#         total_units = float(self.get_parameter('cpu', 'cpu.cfs_period_us'))
#         limit_units = int(self._convert_cpu_limit_to_fraction(limit) * total_units)
#         cpu_shares_file = self._get_cgroup_file('cpu', 'cpu.cfs_quota_us')
#         logger.verbose("writing {0} to {1}".format(limit_units, cpu_shares_file))
#         fileutil.write_file(cpu_shares_file, '{0}\n'.format(limit_units))
#     else:
#         raise CGroupsException("CPU hierarchy not available in this cgroup")
#
# @staticmethod
# def get_num_cores():
#     """
#     Return the number of CPU cores exposed to this system.
#
#     :return: int
#     """
#     return CGroupConfigurator._osutil.get_processor_cores()
#
# @staticmethod
# def _format_memory_value(unit, limit=None):
#     units = {'bytes': 1, 'kilobytes': 1024, 'megabytes': 1024*1024, 'gigabytes': 1024*1024*1024}
#     if unit not in units:
#         raise CGroupsException("Unit must be one of {0}".format(units.keys()))
#     if limit is None:
#         value = MEMORY_DEFAULT
#     else:
#         try:
#             limit = float(limit)
#         except ValueError:
#             raise CGroupsException('Limit must be convertible to a float')
#         else:
#             value = int(limit * units[unit])
#     return value
#
# def set_memory_limit(self, limit=None, unit='megabytes'):
#     if 'memory' in self.cgroups:
#         value = self._format_memory_value(unit, limit)
#         memory_limit_file = self._get_cgroup_file('memory', 'memory.limit_in_bytes')
#         logger.verbose("writing {0} to {1}".format(value, memory_limit_file))
#         fileutil.write_file(memory_limit_file, '{0}\n'.format(value))
#     else:
#         raise CGroupsException("Memory hierarchy not available in this cgroup")
#
# class CGroupsLimits(object):
#     @staticmethod
#     def _get_value_or_default(name, threshold, limit, compute_default):
#         return threshold[limit] if threshold and limit in threshold else compute_default(name)
#
#     def __init__(self, cgroup_name, threshold=None):
#         self.cpu_limit = self._get_value_or_default(cgroup_name, threshold, "cpu", CGroupsLimits.get_default_cpu_limits)
#         self.memory_limit = self._get_value_or_default(cgroup_name, threshold, "memory",
#                                                        CGroupsLimits.get_default_memory_limits)
#
#     @staticmethod
#     def get_default_cpu_limits(cgroup_name):
#         # default values
#         cpu_limit = DEFAULT_CPU_LIMIT_EXT
#         if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
#             cpu_limit = DEFAULT_CPU_LIMIT_AGENT
#         return cpu_limit
#
#     @staticmethod
#     def get_default_memory_limits(cgroup_name):
#         os_util = get_osutil()
#
#         # default values
#         mem_limit = max(DEFAULT_MEM_LIMIT_MIN_MB, round(os_util.get_total_mem() * DEFAULT_MEM_LIMIT_PCT / 100, 0))
#
#         # agent values
#         if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
#             mem_limit = min(DEFAULT_MEM_LIMIT_MAX_MB, mem_limit)
#         return mem_limit
