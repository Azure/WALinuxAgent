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
import threading
from collections import namedtuple
from datetime import datetime as dt

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, CGroupContollers
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import EVERY_SIX_HOURS
from azurelinuxagent.common.resourceusage import MemoryResourceUsage, ProcessInfo

MetricValue = namedtuple('Metric', ['category', 'counter', 'instance', 'value'])
StatmMetricValue = namedtuple('StatmMetricValue', ['pid_name_cmdline', 'resource_metric'])

DELIM = " | "
DEFAULT_PROCESS_NAME = "NO_PROCESS_FOUND"
DEFAULT_PROCESS_COMMANDLINE = "NO_CMDLINE_FOUND"


class MetricsCategory(object):
    MEMORY_CATEGORY = "Memory"
    PROCESS_CATEGORY = "Process"


class MetricsCounter(object):
    PROCESSOR_PERCENT_TIME = "% Processor Time"
    TOTAL_MEM_USAGE = "Total Memory Usage"
    MAX_MEM_USAGE = "Max Memory Usage"
    MEM_USED_BY_PROCESS = "Memory Used by Process"


class CGroupsTelemetry(object):
    """
    """
    _tracked = []
    _cgroup_metrics = {}
    _rlock = threading.RLock()

    @staticmethod
    def get_process_info_summary(process_id):
        process_cmdline = DEFAULT_PROCESS_COMMANDLINE
        process_name = DEFAULT_PROCESS_NAME

        # The ProcessName and ProcessCommandLine can generate Exception if the file /proc/<pid>/{comm,cmdline} cease to
        # exist; eg: the process can die, or finish. Which is why we need Default Names, in case we fail to fetch the
        # details from those files.
        try:
            process_cmdline = ProcessInfo.get_proc_cmdline(process_id) if not None else DEFAULT_PROCESS_COMMANDLINE
        except Exception as e:
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] {0}", ustr(e))

        try:
            process_name = ProcessInfo.get_proc_name(process_id) if not None else DEFAULT_PROCESS_NAME
        except Exception as e:
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] {0}", ustr(e))

        return process_id + DELIM + process_name + DELIM + process_cmdline

    @staticmethod
    def _get_metrics_list(metric):
        return [metric.average(), metric.min(), metric.max(), metric.median(), metric.count(),
                metric.first_poll_time(), metric.last_poll_time()]

    @staticmethod
    def _process_cgroup_metric(cgroup_metrics):
        memory_usage = cgroup_metrics.get_memory_metrics()
        max_memory_usage = cgroup_metrics.get_max_memory_metrics()
        cpu_usage = cgroup_metrics.get_cpu_metrics()
        memory_usage_per_process = cgroup_metrics.get_proc_statm_memory_metrics()

        processed_extension = {}

        if cpu_usage.count() > 0:
            processed_extension["cpu"] = {"cur_cpu": CGroupsTelemetry._get_metrics_list(cpu_usage)}

        if memory_usage.count() > 0:
            if "memory" in processed_extension:
                processed_extension["memory"]["cur_mem"] = CGroupsTelemetry._get_metrics_list(memory_usage)
            else:
                processed_extension["memory"] = {"cur_mem": CGroupsTelemetry._get_metrics_list(memory_usage)}

        if max_memory_usage.count() > 0:
            if "memory" in processed_extension:
                processed_extension["memory"]["max_mem"] = CGroupsTelemetry._get_metrics_list(max_memory_usage)
            else:
                processed_extension["memory"] = {"max_mem": CGroupsTelemetry._get_metrics_list(max_memory_usage)}

        for pid_process_memory in memory_usage_per_process:
            if "proc_statm_memory" in processed_extension:
                processed_extension["proc_statm_memory"][pid_process_memory.pid_name_cmdline] = \
                    CGroupsTelemetry._get_metrics_list(pid_process_memory.resource_metric)
            else:
                processed_extension["proc_statm_memory"] = {pid_process_memory.pid_name_cmdline:
                    CGroupsTelemetry._get_metrics_list(pid_process_memory.resource_metric)}

        return processed_extension

    @staticmethod
    def track_cgroup(cgroup):
        """
        Adds the given item to the dictionary of tracked cgroups
        """
        if isinstance(cgroup, CpuCgroup):
            # set the current cpu usage
            cgroup.initialize_cpu_usage()

        with CGroupsTelemetry._rlock:
            if not CGroupsTelemetry.is_tracked(cgroup.path):
                CGroupsTelemetry._tracked.append(cgroup)
                logger.info("Started tracking new cgroup: {0}, path: {1}".format(cgroup.name, cgroup.path))

    @staticmethod
    def is_tracked(path):
        """
        Returns true if the given item is in the list of tracked items
        O(n) operation. But limited to few cgroup objects we have.
        """
        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked:
                if path == cgroup.path:
                    return True

        return False

    @staticmethod
    def stop_tracking(cgroup):
        """
        Stop tracking the cgroups for the given name
        """
        with CGroupsTelemetry._rlock:
            CGroupsTelemetry._tracked.remove(cgroup)
            logger.info("Stopped tracking cgroup: {0}, path: {1}".format(cgroup.name, cgroup.path))

    @staticmethod
    def report_all_tracked():
        """
        The report_all_tracked's purpose is to collect the data from the tracked cgroups and process the metric into a
        data structure by _process_cgroup_metric. The perf metric is added into the data structure and returned to the
        caller.

        The report_all_tracked would be removed soon - in favor of sending report_metric directly, when polling the data
        from tracked groups.

        :return collected_metrics: dictionary of cgroups metrics.
        """
        collected_metrics = {}

        for name, cgroup_metrics in CGroupsTelemetry._cgroup_metrics.items():
            perf_metric = CGroupsTelemetry._process_cgroup_metric(cgroup_metrics)

            if perf_metric:
                collected_metrics[name] = perf_metric

            cgroup_metrics.clear()

        # Doing cleanup after the metrics have already been collected.
        for key in [key for key in CGroupsTelemetry._cgroup_metrics if
                    CGroupsTelemetry._cgroup_metrics[key].marked_for_delete]:
            del CGroupsTelemetry._cgroup_metrics[key]

        return collected_metrics

    @staticmethod
    def poll_all_tracked():
        metrics = []

        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked[:]:
                if cgroup.name not in CGroupsTelemetry._cgroup_metrics:
                    CGroupsTelemetry._cgroup_metrics[cgroup.name] = CgroupMetrics()
                try:
                    if cgroup.controller == CGroupContollers.CPU:
                        current_cpu_usage = cgroup.get_cpu_usage()
                        CGroupsTelemetry._cgroup_metrics[cgroup.name].add_cpu_usage(current_cpu_usage)
                        metrics.append(MetricValue(MetricsCategory.PROCESS_CATEGORY, MetricsCounter.
                                                   PROCESSOR_PERCENT_TIME, cgroup.name, current_cpu_usage))
                    elif cgroup.controller == CGroupContollers.MEMORY:
                        current_memory_usage = cgroup.get_memory_usage()
                        CGroupsTelemetry._cgroup_metrics[cgroup.name].add_memory_usage(current_memory_usage)
                        metrics.append(MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.
                                                   TOTAL_MEM_USAGE, cgroup.name, current_memory_usage))

                        max_memory_usage = cgroup.get_max_memory_usage()
                        CGroupsTelemetry._cgroup_metrics[cgroup.name].add_max_memory_usage(max_memory_usage)
                        metrics.append(MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MAX_MEM_USAGE,
                                                   cgroup.name, max_memory_usage))

                        pids = cgroup.get_tracked_processes()
                        for pid in pids:
                            try:
                                mem_usage_from_procstatm = MemoryResourceUsage.get_memory_usage_from_proc_statm(pid)
                                metrics.append(MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.
                                                           MEM_USED_BY_PROCESS, CGroupsTelemetry.get_process_info_summary(pid),
                                                           mem_usage_from_procstatm))
                                CGroupsTelemetry._cgroup_metrics[cgroup.name].add_proc_statm_memory(
                                    CGroupsTelemetry.get_process_info_summary(pid), mem_usage_from_procstatm)
                            except Exception as e:
                                if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:
                                    logger.periodic_warn(logger.EVERY_HOUR, "[PERIODIC] Could not collect proc_statm "
                                                                            "for pid {0}. Error : {1}", pid, ustr(e))
                    else:
                        raise CGroupsException('CGroup controller {0} is not supported for cgroup {1}'.format(
                            cgroup.controller, cgroup.name))
                except Exception as e:
                    # There can be scenarios when the CGroup has been deleted by the time we are fetching the values
                    # from it. This would raise IOError with file entry not found (ERRNO: 2). We do not want to log
                    # every occurrences of such case as it would be very verbose. We do want to log all the other
                    # exceptions which could occur, which is why we do a periodic log for all the other errors.
                    if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:
                        logger.periodic_warn(logger.EVERY_HOUR, '[PERIODIC] Could not collect metrics for cgroup '
                                                                '{0}. Error : {1}'.format(cgroup.name, ustr(e)))
                if not cgroup.is_active():
                    CGroupsTelemetry.stop_tracking(cgroup)
                    CGroupsTelemetry._cgroup_metrics[cgroup.name].marked_for_delete = True

        return metrics

    @staticmethod
    def prune_all_tracked():
        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked[:]:
                if not cgroup.is_active():
                    CGroupsTelemetry.stop_tracking(cgroup)

    @staticmethod
    def reset():
        with CGroupsTelemetry._rlock:
            CGroupsTelemetry._tracked *= 0  # emptying the list
            CGroupsTelemetry._cgroup_metrics = {}


class CgroupMetrics(object):
    def __init__(self):
        self._memory_usage = Metric()
        self._max_memory_usage = Metric()
        self._cpu_usage = Metric()
        self._proc_statm_mem = {}

        self.marked_for_delete = False

    def add_memory_usage(self, usage):
        if not self.marked_for_delete:
            self._memory_usage.append(usage)

    def add_max_memory_usage(self, usage):
        if not self.marked_for_delete:
            self._max_memory_usage.append(usage)

    def add_cpu_usage(self, usage):
        if not self.marked_for_delete:
            self._cpu_usage.append(usage)

    def add_proc_statm_memory(self, pid, usage):
        if not self.marked_for_delete:
            if pid not in self._proc_statm_mem:
                self._proc_statm_mem[pid] = Metric()
            self._proc_statm_mem[pid].append(usage)

    def get_memory_metrics(self):
        return self._memory_usage

    def get_max_memory_metrics(self):
        return self._max_memory_usage

    def get_cpu_metrics(self):
        return self._cpu_usage

    def get_proc_statm_memory_metrics(self):
        """
        :return: StatmMetricValue tuples of pid and metric
        """
        return [StatmMetricValue(pid_name_cmdline, metric) for pid_name_cmdline, metric in self._proc_statm_mem.items()]

    def clear(self):
        self._memory_usage.clear()
        self._max_memory_usage.clear()
        self._cpu_usage.clear()
        self._proc_statm_mem.clear()


class Metric(object):
    def __init__(self):
        self._data = []
        self._first_poll_time = None
        self._last_poll_time = None

    def append(self, data):
        if not self._first_poll_time:
            #  We only want to do it first time.
            self._first_poll_time = dt.utcnow()

        self._data.append(data)
        self._last_poll_time = dt.utcnow()

    def clear(self):
        self._first_poll_time = None
        self._last_poll_time = None
        self._data *= 0

    def average(self):
        return float(sum(self._data)) / float(len(self._data)) if self._data else None

    def max(self):
        return max(self._data) if self._data else None

    def min(self):
        return min(self._data) if self._data else None

    def median(self):
        data = sorted(self._data)
        l_len = len(data)
        if l_len < 1:
            return None
        if l_len % 2 == 0:
            return (data[int((l_len - 1) / 2)] + data[int((l_len + 1) / 2)]) / 2.0
        else:
            return data[int((l_len - 1) / 2)]

    def count(self):
        return len(self._data)

    def first_poll_time(self):
        return str(self._first_poll_time)

    def last_poll_time(self):
        return str(self._last_poll_time)
