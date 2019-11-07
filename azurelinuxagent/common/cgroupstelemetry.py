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
from datetime import datetime as dt

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.exception import CGroupsException


class CGroupsTelemetry(object):
    """
    """
    _tracked = []
    _cgroup_metrics = {}
    _rlock = threading.RLock()

    @staticmethod
    def _get_metrics_list(metric):
        return [metric.average(), metric.min(), metric.max(), metric.median(), metric.count(),
                metric.first_poll_time(), metric.last_poll_time()]

    @staticmethod
    def _process_cgroup_metric(cgroup_metrics):
        memory_usage = cgroup_metrics.get_memory_usage()
        max_memory_usage = cgroup_metrics.get_max_memory_usage()
        cpu_usage = cgroup_metrics.get_cpu_usage()

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

        return processed_extension

    @staticmethod
    def track_cgroup(cgroup):
        """
        Adds the given item to the dictionary of tracked cgroups
        """
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
        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked[:]:

                if cgroup.name not in CGroupsTelemetry._cgroup_metrics:
                    CGroupsTelemetry._cgroup_metrics[cgroup.name] = CgroupMetrics()

                CGroupsTelemetry._cgroup_metrics[cgroup.name].collect_data(cgroup)

                if not cgroup.is_active():
                    CGroupsTelemetry.stop_tracking(cgroup)
                    CGroupsTelemetry._cgroup_metrics[cgroup.name].marked_for_delete = True

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
        self.marked_for_delete = False

    def collect_data(self, cgroup):
        # noinspection PyBroadException
        try:
            if cgroup.controller == "cpu":
                self._cpu_usage.append(cgroup.get_cpu_usage())
            elif cgroup.controller == "memory":
                self._memory_usage.append(cgroup.get_memory_usage())
                self._max_memory_usage.append(cgroup.get_max_memory_usage())
            else:
                raise CGroupsException('CGroup controller {0} is not supported'.format(controller))
        except Exception as e:
            if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:
                logger.periodic_warn(logger.EVERY_HALF_HOUR, 'Could not collect metrics for cgroup {0}. Error : {1}'.format(cgroup.path, ustr(e)))

    def get_memory_usage(self):
        return self._memory_usage

    def get_max_memory_usage(self):
        return self._max_memory_usage

    def get_cpu_usage(self):
        return self._cpu_usage

    def clear(self):
        self._memory_usage.clear()
        self._max_memory_usage.clear()
        self._cpu_usage.clear()


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
