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

import time

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator

related_services = {
    "Microsoft.OSTCExtensions.LinuxDiagnostic":    ["omid", "omsagent-LAD", "mdsd-lde"],
    "Microsoft.Azure.Diagnostics.LinuxDiagnostic": ["omid", "omsagent-LAD", "mdsd-lde"],
}

class CGroupsTelemetry(object):
    """
    Encapsulate the cgroup-based telemetry for the agent or one of its extensions, or for the aggregation across
    the agent and all of its extensions. These objects should have lifetimes that span the time window over which
    measurements are desired; in general, they're not terribly effective at providing instantaneous measurements.
    """
    _tracked = {}
    _metrics = {
        "cpu": CpuCgroup,
        "memory": MemoryCGroup
    }
    _hierarchies = list(_metrics.keys())

    tracked_names = set()

    @staticmethod
    def metrics_hierarchies():
        return CGroupsTelemetry._hierarchies

    @staticmethod
    def track_cgroup(cgroup):
        """
        Create a CGroupsTelemetry object to track a particular CGroups instance. Typical usage:
        1) Create a CGroups object
        2) Ask CGroupsTelemetry to track it
        3) Tell the CGroups object to add one or more processes (or let systemd handle that, for its cgroups)

        :param CGroupConfigurator cgroup: The cgroup to track
        """
        name = cgroup.name
        if CGroupConfigurator.enabled() and not CGroupsTelemetry.is_tracked(name):
            tracker = CGroupsTelemetry(name, cgroup=cgroup)
            CGroupsTelemetry._tracked[name] = tracker

    @staticmethod
    def track_systemd_service(name):
        """
        If not already tracking it, create the CGroups object for a systemd service and track it.

        :param str name: Service name (without .service suffix) to be tracked.
        """
        service_name = "{0}.service".format(name).lower()
        if CGroupConfigurator.enabled() and not CGroupsTelemetry.is_tracked(service_name):
            cgroup = CGroupConfigurator.for_systemd_service(service_name)
            logger.info("Now tracking cgroup {0}".format(service_name))
            tracker = CGroupsTelemetry(service_name, cgroup=cgroup)
            CGroupsTelemetry._tracked[service_name] = tracker

    @staticmethod
    def track_extension(name, cgroup=None):
        """
        Create all required CGroups to track all metrics for an extension and its associated services.

        :param str name: Full name of the extension to be tracked
        :param CGroupConfigurator cgroup: CGroup for the extension itself. This method will create it if none is supplied.
        """
        if not CGroupConfigurator.enabled():
            return

        if not CGroupsTelemetry.is_tracked(name):
            cgroup = CGroupConfigurator.for_extension(name) if cgroup is None else cgroup
            logger.info("Now tracking cgroup {0}".format(name))
            cgroup.set_limits()
            CGroupsTelemetry.track_cgroup(cgroup)
        if CGroupConfigurator.is_systemd_manager():
            if name in related_services:
                for service_name in related_services[name]:
                    CGroupsTelemetry.track_systemd_service(service_name)

    @staticmethod
    def track_agent():
        """
        Create and track the correct cgroup for the agent itself. The actual cgroup depends on whether systemd
        is in use, but the caller doesn't need to know that.
        """
        if not CGroupConfigurator.enabled():
            return
        if CGroupConfigurator.is_systemd_manager():
            logger.info("Tracking systemd cgroup for {0}".format(AGENT_CGROUP_NAME))
            CGroupsTelemetry.track_systemd_service(AGENT_CGROUP_NAME)
        else:
            logger.info("Tracking cgroup for {0}".format(AGENT_CGROUP_NAME))
            # This creates /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent
            CGroupsTelemetry.track_cgroup(CGroupConfigurator.for_extension(AGENT_CGROUP_NAME))

    @staticmethod
    def is_tracked(name):
        return name in CGroupsTelemetry._tracked

    @staticmethod
    def stop_tracking(name):
        """
        Stop tracking telemetry for the CGroups associated with an extension. If any system services are being
        tracked, those will continue to be tracked; multiple extensions might rely upon the same service.

        :param str name: Extension to be dropped from tracking
        """
        if CGroupsTelemetry.is_tracked(name):
            del (CGroupsTelemetry._tracked[name])

    @staticmethod
    def collect_all_tracked():
        """
        Return a dictionary mapping from the name of a tracked cgroup to the list of collected metrics for that cgroup.
        Collecting metrics is not guaranteed to be a fast operation; it's possible some other thread might add or remove
        tracking for a cgroup while we're doing it. To avoid "dictionary changed size during iteration" exceptions,
        work from a shallow copy of the _tracked dictionary.

        :returns: Dictionary of list collected metrics (metric class, metric name, value), by cgroup
        :rtype: dict(str: [(str, str, float)])
        """
        results = {}
        limits = {}

        for cgroup_name, collector in CGroupsTelemetry._tracked.copy().items():
            results[cgroup_name] = collector.collect()
            limits[cgroup_name] = collector.cgroup.threshold

        return results, limits

    @staticmethod
    def update_tracked(ext_handlers):
        """
        Track CGroups for all enabled extensions.
        Track CGroups for services created by enabled extensions.
        Stop tracking CGroups for not-enabled extensions.

        :param List(ExtHandler) ext_handlers:
        """
        if not CGroupConfigurator.enabled():
            return

        not_enabled_extensions = set()
        for extension in ext_handlers:
            if extension.properties.state == u"enabled":
                CGroupsTelemetry.track_extension(extension.name)
            else:
                not_enabled_extensions.add(extension.name)

        names_now_tracked = set(CGroupsTelemetry._tracked.keys())
        if CGroupsTelemetry.tracked_names != names_now_tracked:
            now_tracking = " ".join("[{0}]".format(name) for name in sorted(names_now_tracked))
            if len(now_tracking):
                logger.info("After updating cgroup telemetry, tracking {0}".format(now_tracking))
            else:
                logger.warn("After updating cgroup telemetry, tracking no cgroups.")
            CGroupsTelemetry.tracked_names = names_now_tracked

    def __init__(self, name, cgroup=None):
        """
        Create the necessary state to collect metrics for the agent, one of its extensions, or the aggregation across
        the agent and all of its extensions. To access aggregated metrics, instantiate this object with an empty string
        or None.

        :param name: str
        """
        if name is None:
            name = ""
        self.name = name
        if cgroup is None:
            cgroup = CGroupConfigurator.for_extension(name)
        self.cgroup = cgroup
        self.cpu_count = CGroupConfigurator.get_num_cores()
        self.current_wall_time = time.time()
        self.previous_wall_time = 0

        self.data = {}
        if CGroupConfigurator.enabled():
            for hierarchy in CGroupsTelemetry.metrics_hierarchies():
                self.data[hierarchy] = CGroupsTelemetry._metrics[hierarchy](self)

    def collect(self):
        """
        Return a list of collected metrics. Each element is a tuple of
        (metric group name, metric name, metric value)
        :return: [(str, str, float)]
        """
        results = []
        for collector in self.data.values():
            results.extend(collector.collect())
        return results

