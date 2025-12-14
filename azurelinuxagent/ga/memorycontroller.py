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

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.cgroupcontroller import _CgroupController, CounterNotFound, MetricValue, MetricsCategory, \
    MetricsCounter, _REPORT_EVERY_HOUR


class _MemoryController(_CgroupController):
    def __init__(self, name, cgroup_path):
        super(_MemoryController, self).__init__(name, cgroup_path)
        self._counter_not_found_error_count = 0

    def _get_memory_stat_counter(self, counter_name):
        """
        Gets the value for the provided counter in memory.stat
        """
        try:
            with open(os.path.join(self.path, 'memory.stat')) as memory_stat:
                #
                # Sample file v1:
                #   # cat memory.stat
                #   cache 0
                #   rss 0
                #   rss_huge 0
                #   shmem 0
                #   mapped_file 0
                #   dirty 0
                #   writeback 0
                #   swap 0
                #   ...
                #
                # Sample file v2
                #   # cat memory.stat
                #   anon 0
                #   file 147140608
                #   kernel 1421312
                #   kernel_stack 0
                #   pagetables 0
                #   sec_pagetables 0
                #   percpu 130752
                #   sock 0
                #   ...
                #
                for line in memory_stat:
                    re_memory_counter = r'{0}\s+(\d+)'.format(counter_name)
                    match = re.match(re_memory_counter, line)
                    if match is not None:
                        return int(match.groups()[0])
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                raise
            raise CGroupsException("Failed to read memory.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read memory.stat: {0}".format(ustr(e)))

        raise CounterNotFound("Cannot find counter: {0}".format(counter_name))

    def get_memory_usage(self):
        """
        Collects anon and cache usage for the cgroup and returns as a tuple
        Returns anon and cache memory usage for the cgroup as a tuple ->  (anon, cache)

        :return: Anon and cache memory usage in bytes
        :rtype: tuple[int, int]
        """
        raise NotImplementedError()

    def try_swap_memory_usage(self):
        """
        Collects swap usage for the cgroup

        :return: Memory usage in bytes
        :rtype: int
        """
        raise NotImplementedError()

    def get_max_memory_usage(self):
        """
        Collect max memory usage for the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        raise NotImplementedError()

    def get_tracked_metrics(self, **_):
        # The log collector monitor tracks anon and cache memory separately.
        anon_mem_usage, cache_mem_usage = self.get_memory_usage()
        total_mem_usage = anon_mem_usage + cache_mem_usage
        return [
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_MEM_USAGE, self.name, total_mem_usage),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.ANON_MEM_USAGE, self.name, anon_mem_usage),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.CACHE_MEM_USAGE, self.name, cache_mem_usage),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MAX_MEM_USAGE, self.name,
                        self.get_max_memory_usage(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.SWAP_MEM_USAGE, self.name,
                        self.try_swap_memory_usage(), _REPORT_EVERY_HOUR)
        ]

    def get_unit_properties(self):
        return ["MemoryAccounting"]

    def get_controller_type(self):
        return "memory"


class MemoryControllerV1(_MemoryController):
    def get_memory_usage(self):
        # In v1, anon memory is reported in the 'rss' counter
        return self._get_memory_stat_counter("rss"), self._get_memory_stat_counter("cache")

    def try_swap_memory_usage(self):
        # In v1, swap memory should be collected from memory.stat, because memory.memsw.usage_in_bytes reports total Memory+SWAP.
        try:
            return self._get_memory_stat_counter("swap")
        except CounterNotFound as e:
            if self._counter_not_found_error_count < 1:
                logger.periodic_info(logger.EVERY_HALF_HOUR,
                                     '{0} from "memory.stat" file in the cgroup: {1}---[Note: This log for informational purpose only and can be ignored]'.format(ustr(e), self.path))
                self._counter_not_found_error_count += 1
            return 0

    def get_max_memory_usage(self):
        # In v1, max memory usage is reported in memory.max_usage_in_bytes
        usage = 0
        try:
            usage = int(self._get_parameters('memory.max_usage_in_bytes', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.max_usage_in_bytes"), e)

        return usage


class MemoryControllerV2(_MemoryController):
    def get_memory_usage(self):
        # In v2, cache memory is reported in the 'file' counter
        return self._get_memory_stat_counter("anon"), self._get_memory_stat_counter("file")

    def get_unit_properties(self):
        properties = super(MemoryControllerV2, self).get_unit_properties()
        properties.append("MemoryHigh")
        return properties

    def get_memory_pressure_events(self):
        """
        We use the share of time in which processes of the cgroup have experienced memory pressure.
        :return: Total time some processes stalled due to memory pressure in last 300 seconds
        :rtype: float
        Note: we get 0 if process not stalled or we return explict 0 if file is not present which is expected in some distros.
        But we don't consider 0 values in the metrics report as they are not meaningful data, so no need to worry about false zeros.
        """
        try:
            with open(os.path.join(self.path, 'memory.pressure')) as memory_pressure:
                #
                # Sample file:
                #   # cat memory.pressure
                #   some avg10=0.00 avg60=0.00 avg300=0.00 total=0
                #   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
                #
                for line in memory_pressure:
                    match = re.search(r'avg300=([0-9.]+)', line)
                    if match is not None:
                        percentage = float(match.group(1))
                        time_spent = 300 * (percentage / 100)
                        return round(time_spent,  2)
        except (IOError, OSError) as e:
            if e.errno != errno.ENOENT:  # File is not present in some distros, so we do not raise in that case
                raise CGroupsException("Failed to read memory.pressure: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read memory.pressure: {0}".format(ustr(e)))

        return float(0)

    def get_memory_throttled_events(self):
        """
        Returns the number of times processes of the cgroup are throttled and routed to perform memory recliam because
        the high memory boundary was exceeded.

        :return: Number of memory throttling events for the cgroup
        :rtype: int
        """
        try:
            with open(os.path.join(self.path, 'memory.events')) as memory_events:
                #
                # Sample file:
                #   # cat memory.events
                #   low 0
                #   high 0
                #   max 0
                #   oom 0
                #   oom_kill 0
                #   oom_group_kill 0
                #
                for line in memory_events:
                    match = re.match(r'high\s+(\d+)', line)
                    if match is not None:
                        return int(match.groups()[0])
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                raise
            raise CGroupsException("Failed to read memory.events: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read memory.events: {0}".format(ustr(e)))

        raise CounterNotFound("Cannot find memory.events counter: high")

    def try_swap_memory_usage(self):
        # In v2, swap memory is reported in memory.swap.current
        usage = 0
        try:
            usage = int(self._get_parameters('memory.swap.current', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.swap.current"), e)

        return usage

    def get_max_memory_usage(self):
        # In v2, max memory usage is reported in memory.peak
        usage = 0
        try:
            usage = int(self._get_parameters('memory.peak', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.peak"), e)

        return usage

    def get_tracked_metrics(self, **_):
        metrics = super(MemoryControllerV2, self).get_tracked_metrics()
        throttled_value = MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MEM_THROTTLED, self.name,
                                      self.get_memory_throttled_events())
        metrics.append(throttled_value)
        pressure_value = self.get_memory_pressure_events()
        if pressure_value > float(0):  # Only report if there is any memory pressure
            metrics.append(MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MEM_PRESSURE, self.name, pressure_value))
        return metrics
