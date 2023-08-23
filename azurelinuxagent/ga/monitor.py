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
#

import datetime
import os
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.networkutil as networkutil
from azurelinuxagent.ga.cgroup import MetricValue, MetricsCategory, MetricsCounter
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_metric
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.utils.textutil import hash_strings
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_monitor_handler():
    return MonitorHandler()


class PollResourceUsage(PeriodicOperation):
    """
    Periodic operation to poll the tracked cgroups for resource usage data.

    It also checks whether there are processes in the agent's cgroup that should not be there.

    """
    def __init__(self):
        super(PollResourceUsage, self).__init__(conf.get_cgroup_check_period())
        self.__log_metrics = conf.get_cgroup_log_metrics()
        self.__periodic_metrics = {}

    def _operation(self):
        tracked_metrics = CGroupsTelemetry.poll_all_tracked()

        for metric in tracked_metrics:
            key = metric.category + metric.counter + metric.instance
            if key not in self.__periodic_metrics or (self.__periodic_metrics[key] + metric.report_period) <= datetime.datetime.now():
                report_metric(metric.category, metric.counter, metric.instance, metric.value, log_event=self.__log_metrics)
                self.__periodic_metrics[key] = datetime.datetime.now()

        CGroupConfigurator.get_instance().check_cgroups(tracked_metrics)


class PollSystemWideResourceUsage(PeriodicOperation):
    def __init__(self):
        super(PollSystemWideResourceUsage, self).__init__(datetime.timedelta(hours=1))
        self.__log_metrics = conf.get_cgroup_log_metrics()
        self.osutil = get_osutil()

    def poll_system_memory_metrics(self):
        used_mem, available_mem = self.osutil.get_used_and_available_system_memory()
        return [
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.USED_MEM, "",
                        used_mem),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.AVAILABLE_MEM, "",
                        available_mem)
        ]

    def _operation(self):
        metrics = self.poll_system_memory_metrics()
        for metric in metrics:
            report_metric(metric.category, metric.counter, metric.instance, metric.value, log_event=self.__log_metrics)


class ResetPeriodicLogMessages(PeriodicOperation):
    """
    Periodic operation to clean up the hash-tables maintained by the loggers. For reference, please check
    azurelinuxagent.common.logger.Logger and azurelinuxagent.common.event.EventLogger classes
    """
    def __init__(self):
        super(ResetPeriodicLogMessages, self).__init__(datetime.timedelta(hours=12))

    def _operation(self):
        logger.reset_periodic()


class ReportNetworkErrors(PeriodicOperation):
    def __init__(self):
        super(ReportNetworkErrors, self).__init__(datetime.timedelta(minutes=30))

    def _operation(self):
        io_errors = IOErrorCounter.get_and_reset()
        hostplugin_errors = io_errors.get("hostplugin")
        protocol_errors = io_errors.get("protocol")
        other_errors = io_errors.get("other")

        if hostplugin_errors > 0 or protocol_errors > 0 or other_errors > 0:
            msg = "hostplugin:{0};protocol:{1};other:{2}".format(hostplugin_errors, protocol_errors, other_errors)
            add_event(op=WALAEventOperation.HttpErrors, message=msg)


class ReportNetworkConfigurationChanges(PeriodicOperation):
    """
    Periodic operation to check and log changes in network configuration.
    """
    def __init__(self):
        super(ReportNetworkConfigurationChanges, self).__init__(datetime.timedelta(minutes=1))
        self.osutil = get_osutil()
        self.last_route_table_hash = b''
        self.last_nic_state = {}

    def log_network_configuration(self):
        try:
            route_file = '/proc/net/route'
            if os.path.exists(route_file):
                lines = []
                with open(route_file) as file_object:
                    for line in file_object:
                        lines.append(line)
                        if len(lines) >= 100:
                            lines.append("<TRUNCATED TO {0} LINES".format(len(lines)))
                            break
                logger.info("Routing table from {0}:\n{1}", route_file, ''.join(lines))
            network_interfaces = self.osutil.get_nic_state(as_string=True)
            if network_interfaces != '':
                logger.info("Network interfaces:\n{0}", network_interfaces)
        except Exception as exception:
            logger.warn("Error fetching the network configuration: {0}", ustr(exception))

    def _operation(self):
        raw_route_list = self.osutil.read_route_table()
        digest = hash_strings(raw_route_list)
        if digest != self.last_route_table_hash:
            self.last_route_table_hash = digest
            route_list = self.osutil.get_list_of_routes(raw_route_list)
            logger.info("Route table: [{0}]".format(",".join(map(networkutil.RouteEntry.to_json, route_list))))

        nic_state = self.osutil.get_nic_state()
        if nic_state != self.last_nic_state:
            description = "Initial" if self.last_nic_state == {} else "Updated"
            logger.info("{0} NIC state: [{1}]".format(description, ", ".join(map(str, nic_state.values()))))
            self.last_nic_state = nic_state


class SendHostPluginHeartbeat(PeriodicOperation):
    """
    Periodic operation for reporting the HostGAPlugin's health. The signal is 'Healthy' when we have been able to communicate with
    plugin at least once in the last _HOST_PLUGIN_HEALTH_PERIOD.
    """
    def __init__(self, protocol, health_service):
        super(SendHostPluginHeartbeat, self).__init__(SendHostPluginHeartbeat._HOST_PLUGIN_HEARTBEAT_PERIOD)
        self.protocol = protocol
        self.health_service = health_service
        self.host_plugin_error_state = ErrorState(min_timedelta=SendHostPluginHeartbeat._HOST_PLUGIN_HEALTH_PERIOD)

    _HOST_PLUGIN_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    _HOST_PLUGIN_HEALTH_PERIOD = datetime.timedelta(minutes=5)

    def _operation(self):
        try:
            host_plugin = self.protocol.client.get_host_plugin()
            host_plugin.ensure_initialized()
            self.protocol.update_host_plugin_from_goal_state()

            is_currently_healthy = host_plugin.get_health()

            if is_currently_healthy:
                self.host_plugin_error_state.reset()
            else:
                self.host_plugin_error_state.incr()

            is_healthy = self.host_plugin_error_state.is_triggered() is False
            logger.verbose("HostGAPlugin health: {0}", is_healthy)

            self.health_service.report_host_plugin_heartbeat(is_healthy)

            if not is_healthy:
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.HostPluginHeartbeatExtended,
                    is_success=False,
                    message='{0} since successful heartbeat'.format(self.host_plugin_error_state.fail_time),
                    log_event=False)

        except Exception as e:
            msg = "Exception sending host plugin heartbeat: {0}".format(ustr(e))
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.HostPluginHeartbeat,
                is_success=False,
                message=msg,
                log_event=False)
            raise


class SendImdsHeartbeat(PeriodicOperation):
    """
    Periodic operation to report the IDMS's health. The signal is 'Healthy' when we have successfully called and validated
    a response in the last _IMDS_HEALTH_PERIOD.
    """
    def __init__(self, protocol_util, health_service):
        super(SendImdsHeartbeat, self).__init__(SendImdsHeartbeat._IMDS_HEARTBEAT_PERIOD)
        self.health_service = health_service
        self.imds_client = get_imds_client(protocol_util.get_wireserver_endpoint())
        self.imds_error_state = ErrorState(min_timedelta=SendImdsHeartbeat._IMDS_HEALTH_PERIOD)

    _IMDS_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    _IMDS_HEALTH_PERIOD = datetime.timedelta(minutes=3)

    def _operation(self):
        try:
            is_currently_healthy, response = self.imds_client.validate()

            if is_currently_healthy:
                self.imds_error_state.reset()
            else:
                self.imds_error_state.incr()

            is_healthy = self.imds_error_state.is_triggered() is False
            logger.verbose("IMDS health: {0} [{1}]", is_healthy, response)

            self.health_service.report_imds_status(is_healthy, response)

        except Exception as e:
            msg = "Exception sending imds heartbeat: {0}".format(ustr(e))
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.ImdsHeartbeat,
                is_success=False,
                message=msg,
                log_event=False)
            raise


class MonitorHandler(ThreadHandlerInterface):
    _THREAD_NAME = "MonitorHandler"

    @staticmethod
    def get_thread_name():
        return MonitorHandler._THREAD_NAME

    def __init__(self):
        self.monitor_thread = None
        self.should_run = True

    def run(self):
        self.start()

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.join()

    def join(self):
        self.monitor_thread.join()

    def stopped(self):
        return not self.should_run

    def is_alive(self):
        return self.monitor_thread is not None and self.monitor_thread.is_alive()

    def start(self):
        self.monitor_thread = threading.Thread(target=self.daemon)
        self.monitor_thread.setDaemon(True)
        self.monitor_thread.setName(self.get_thread_name())
        self.monitor_thread.start()

    def daemon(self):
        try:
            # The protocol needs to be instantiated in the monitor thread itself (to avoid concurrency issues with the protocol object each
            # thread uses a different instance as per the SingletonPerThread model.
            protocol_util = get_protocol_util()
            protocol = protocol_util.get_protocol()
            health_service = HealthService(protocol.get_endpoint())
            periodic_operations = [
                ResetPeriodicLogMessages(),
                ReportNetworkErrors(),
                PollResourceUsage(),
                PollSystemWideResourceUsage(),
                SendHostPluginHeartbeat(protocol, health_service),
                SendImdsHeartbeat(protocol_util, health_service)
            ]

            report_network_configuration_changes = ReportNetworkConfigurationChanges()
            if conf.get_monitor_network_configuration_changes():
                periodic_operations.append(report_network_configuration_changes)
            else:
                logger.info("Monitor.NetworkConfigurationChanges is disabled.")
                report_network_configuration_changes.log_network_configuration()

            while not self.stopped():
                try:
                    for op in periodic_operations:
                        op.run()
                finally:
                    PeriodicOperation.sleep_until_next_operation(periodic_operations)
        except Exception as e:
            logger.error("An error occurred in the monitor thread; will exit the thread.\n{0}", ustr(e))


