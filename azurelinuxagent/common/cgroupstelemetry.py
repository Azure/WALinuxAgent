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
import threading
from datetime import datetime as dt


class CGroupsTelemetry(object):
    """
    """
    _tracked = []
    _cgroup_metrics = {}
    _rlock = threading.RLock()

    @staticmethod
    def _get_metrics_list(metric):
        return [metric.average(), metric.min(), metric.max(), metric.median(), metric.count(), metric.first_polltime(),
                metric.last_polltime()]

    @staticmethod
    def _process_cgroup_metric(cgroup_metrics):
        current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metrics.get_metrics()
        processed_extension = {
            "memory": {
                "cur_mem": CGroupsTelemetry._get_metrics_list(current_memory_usage),
                "max_mem": CGroupsTelemetry._get_metrics_list(max_memory_levels)
            },
            "cpu": {
                "cur_cpu": CGroupsTelemetry._get_metrics_list(current_cpu_usage)
            }
        }
        return processed_extension

    @staticmethod
    def metrics_hierarchies():
        pass  # return CGroupsTelemetry._hierarchies

    @staticmethod
    def track_cgroup(cgroup):
        """
        Adds the given item to the dictionary of tracked cgroups
        """
        # Making track thread-safe.
        CGroupsTelemetry._rlock.acquire()
        CGroupsTelemetry._tracked.append(cgroup)
        # if not CGroupsTelemetry.is_tracked(cgroup.name, cgroup.controller):
        #     CGroupsTelemetry._tracked[cgroup.name] = {cgroup.controller: cgroup}

        CGroupsTelemetry._rlock.release()

    @staticmethod
    def is_tracked(name, controller):
        """
        Returns true if the given item is in the list of tracked items
        """
        return name in CGroupsTelemetry._tracked and controller in CGroupsTelemetry._tracked[name]

    @staticmethod
    def stop_tracking(name):
        """
        Stop tracking the cgroups for the given name
        """
        # Pop is atomic and thread-safe.
        return CGroupsTelemetry._tracked.pop(name, None)

    @staticmethod
    def collect_all_tracked():
        collected_metrics = {}
        for name, cgroup_metrics in CGroupsTelemetry._cgroup_metrics.items():
            collected_metrics[name] = CGroupsTelemetry._process_cgroup_metric(cgroup_metrics)
            cgroup_metrics.clear()

        return collected_metrics

    @staticmethod
    def poll_all_tracked():
        CGroupsTelemetry._rlock.acquire()
        for cgroup in CGroupsTelemetry._tracked:
            if cgroup.name not in CGroupsTelemetry._cgroup_metrics:
                CGroupsTelemetry._cgroup_metrics[cgroup.name] = CgroupMetrics()

            CGroupsTelemetry._cgroup_metrics[cgroup.name].add_new_data(cgroup.controller,
                                                                       cgroup.collect())
            if not cgroup.is_active():
                CGroupsTelemetry._tracked.remove(cgroup)

        CGroupsTelemetry._rlock.release()

    @staticmethod
    def prune_all_tracked():
        CGroupsTelemetry._rlock.acquire()
        for cgroup in CGroupsTelemetry._tracked:
            if not cgroup.is_active():
                CGroupsTelemetry._tracked.remove(cgroup)

        CGroupsTelemetry._rlock.release()

    @staticmethod
    def cleanup():
        CGroupsTelemetry._tracked.clear()

    def __init__(self):
        pass
        # TODO


class CgroupMetrics(object):
    def __init__(self):
        self.current_memory_usage = Metric()
        self.max_memory_levels = Metric()
        self.current_cpu_usage = Metric()

    def _add_memory_usage(self, metric):
        self.current_memory_usage.append(metric[0].value)
        self.max_memory_levels.append(metric[1].value)

    def _add_cpu_usage(self, metric):
        self.current_cpu_usage.append(metric[0].value)

    def add_new_data(self, controller, metric):
        if controller is "cpu":
            self._add_cpu_usage(metric)
        elif controller is "memory":
            self._add_memory_usage(metric)

    def get_metrics(self):
        return self.current_memory_usage, self.max_memory_levels, self.current_cpu_usage

    def clear(self):
        self.current_memory_usage.clear()
        self.max_memory_levels.clear()
        self.current_cpu_usage.clear()


class Metric(object):
    def __init__(self):
        self.data = []
        self.first_poll_time = dt.utcnow()
        self.last_poll_time = dt.utcnow()

    def append(self, metric):
        self.data.append(metric)
        self.last_poll_time = dt.utcnow()

    def clear(self):
        self.data.clear()

    def average(self):
        return sum(self.data) / len(self.data)

    def max(self):
        return max(self.data)

    def min(self):
        return min(self.data)

    def median(self):
        data = sorted(self.data)
        l_len = len(data)
        if l_len < 1:
            return None
        if l_len % 2 == 0:
            return (data[int((l_len - 1) / 2)] + data[int((l_len + 1) / 2)]) / 2.0
        else:
            return data[int((l_len - 1) / 2)]

    def count(self):
        return len(self.data)

    def first_polltime(self):
        return str(self.first_poll_time)

    def last_polltime(self):
        return str(self.last_poll_time)


class CpuMetrics(Metric):
    def __init__(self):
        super(CpuMetrics, self).__init__()


class MemoryMetrics(Metric):
    def __init__(self):
        super(MemoryMetrics, self).__init__()
