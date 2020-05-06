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
import threading
import time
import uuid

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.networkutil as networkutil
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_metric, collect_events
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.utils.textutil import hash_strings
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                    performance_metrics=None):
    if schema_version == 1.0:
        telemetry_dict = {"SchemaVersion": 1.0}
        if performance_metrics:
            telemetry_dict["PerfMetrics"] = performance_metrics
        return telemetry_dict
    else:
        return None


def get_monitor_handler():
    return MonitorHandler()


class MonitorHandler(object):
    # telemetry
    EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=1)
    # host health
    TELEMETRY_HEARTBEAT_PERIOD = datetime.timedelta(minutes=30)
    # cgroup data period
    CGROUP_TELEMETRY_POLLING_PERIOD = datetime.timedelta(minutes=5)
    # host plugin
    HOST_PLUGIN_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    HOST_PLUGIN_HEALTH_PERIOD = datetime.timedelta(minutes=5)
    # imds
    IMDS_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    IMDS_HEALTH_PERIOD = datetime.timedelta(minutes=3)
    # log network configuration
    LOG_NETWORK_CONFIGURATION_PERIOD = datetime.timedelta(minutes=1)
    # Resetting loggers period
    RESET_LOGGERS_PERIOD = datetime.timedelta(hours=12)

    def __init__(self):
        self.osutil = get_osutil()
        self.imds_client = None

        self.event_thread = None
        self._reset_loggers_op = PeriodicOperation("reset_loggers", self.reset_loggers, self.RESET_LOGGERS_PERIOD)
        self._collect_and_send_events_op = PeriodicOperation("collect_and_send_events", self.collect_and_send_events, self.EVENT_COLLECTION_PERIOD)
        self._send_telemetry_heartbeat_op = PeriodicOperation("send_telemetry_heartbeat", self.send_telemetry_heartbeat, self.TELEMETRY_HEARTBEAT_PERIOD)
        self._poll_telemetry_metrics_op = PeriodicOperation("poll_telemetry_metrics usage", self.poll_telemetry_metrics, self.CGROUP_TELEMETRY_POLLING_PERIOD)
        self._send_host_plugin_heartbeat_op = PeriodicOperation("send_host_plugin_heartbeat", self.send_host_plugin_heartbeat, self.HOST_PLUGIN_HEARTBEAT_PERIOD)
        self._send_imds_heartbeat_op = PeriodicOperation("send_imds_heartbeat", self.send_imds_heartbeat, self.IMDS_HEARTBEAT_PERIOD)
        self._log_altered_network_configuration_op = PeriodicOperation("log_altered_network_configuration", self.log_altered_network_configuration, self.LOG_NETWORK_CONFIGURATION_PERIOD)
        self.protocol = None
        self.protocol_util = None
        self.health_service = None
        self.last_route_table_hash = b''
        self.last_nic_state = {}

        self.should_run = True
        self.heartbeat_id = str(uuid.uuid4()).upper()
        self.host_plugin_errorstate = ErrorState(min_timedelta=MonitorHandler.HOST_PLUGIN_HEALTH_PERIOD)
        self.imds_errorstate = ErrorState(min_timedelta=MonitorHandler.IMDS_HEALTH_PERIOD)

    def run(self):
        self.start(init_data=True)

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.join()

    def join(self):
        self.event_thread.join()

    def stopped(self):
        return not self.should_run

    def init_protocols(self):
        # The initialization of ProtocolUtil for the Monitor thread should be done within the thread itself rather
        # than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
        # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
        self.protocol_util = get_protocol_util()
        self.protocol = self.protocol_util.get_protocol()
        self.health_service = HealthService(self.protocol.get_endpoint())

    def init_imds_client(self):
        wireserver_endpoint = self.protocol_util.get_wireserver_endpoint()
        self.imds_client = get_imds_client(wireserver_endpoint)

    def is_alive(self):
        return self.event_thread is not None and self.event_thread.is_alive()

    def start(self, init_data=False):
        self.event_thread = threading.Thread(target=self.daemon, args=(init_data,))
        self.event_thread.setDaemon(True)
        self.event_thread.setName("MonitorHandler")
        self.event_thread.start()

    def collect_and_send_events(self):
        """
        Periodically send any events located in the events folder
        """
        event_list = collect_events()

        if len(event_list.events) > 0:
            self.protocol.report_event(event_list)

    def daemon(self, init_data=False):

        if init_data:
            self.init_protocols()
            self.init_imds_client()

        min_delta = min(MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD,
                        MonitorHandler.CGROUP_TELEMETRY_POLLING_PERIOD,
                        MonitorHandler.EVENT_COLLECTION_PERIOD,
                        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD,
                        MonitorHandler.IMDS_HEARTBEAT_PERIOD).seconds
        while not self.stopped():
            try:
                self.protocol.update_host_plugin_from_goal_state()
                self._send_telemetry_heartbeat_op.run()
                self._poll_telemetry_metrics_op.run()
                self._collect_and_send_events_op.run()
                self._send_host_plugin_heartbeat_op.run()
                self._send_imds_heartbeat_op.run()
                self._log_altered_network_configuration_op.run()
                self._reset_loggers_op.run()
            except Exception as e:
                logger.warn("An error occurred in the monitor thread main loop; will skip the current iteration.\n{0}", ustr(e))
            time.sleep(min_delta)

    def reset_loggers(self):
        """
        The loggers maintain hash-tables in memory and they need to be cleaned up from time to time.
        For reference, please check azurelinuxagent.common.logger.Logger and
        azurelinuxagent.common.event.EventLogger classes
        """
        logger.reset_periodic()

    def send_imds_heartbeat(self):
        """
        Send a health signal every IMDS_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have
        successfully called and validated a response in the last IMDS_HEALTH_PERIOD.
        """
        try:
            is_currently_healthy, response = self.imds_client.validate()

            if is_currently_healthy:
                self.imds_errorstate.reset()
            else:
                self.imds_errorstate.incr()

            is_healthy = self.imds_errorstate.is_triggered() is False
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

    def send_host_plugin_heartbeat(self):
        """
        Send a health signal every HOST_PLUGIN_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have been able to
        communicate with HostGAPlugin at least once in the last HOST_PLUGIN_HEALTH_PERIOD.
        """
        try:
            host_plugin = self.protocol.client.get_host_plugin()
            host_plugin.ensure_initialized()
            is_currently_healthy = host_plugin.get_health()

            if is_currently_healthy:
                self.host_plugin_errorstate.reset()
            else:
                self.host_plugin_errorstate.incr()

            is_healthy = self.host_plugin_errorstate.is_triggered() is False
            logger.verbose("HostGAPlugin health: {0}", is_healthy)

            self.health_service.report_host_plugin_heartbeat(is_healthy)

            if not is_healthy:
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.HostPluginHeartbeatExtended,
                    is_success=False,
                    message='{0} since successful heartbeat'.format(self.host_plugin_errorstate.fail_time),
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

    def send_telemetry_heartbeat(self):
        io_errors = IOErrorCounter.get_and_reset()
        hostplugin_errors = io_errors.get("hostplugin")
        protocol_errors = io_errors.get("protocol")
        other_errors = io_errors.get("other")

        if hostplugin_errors > 0 or protocol_errors > 0 or other_errors > 0:
            msg = "hostplugin:{0};protocol:{1};other:{2}".format(hostplugin_errors, protocol_errors,
                                                                 other_errors)
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.HttpErrors,
                is_success=True,
                message=msg,
                log_event=False)

    def poll_telemetry_metrics(self):
        """
        This method polls the tracked cgroups to get data from the cgroups filesystem and send it to the performance counters database.

        :return: List of Metrics (which would be sent to PerfCounterMetrics directly.
        """
        metrics = CGroupsTelemetry.poll_all_tracked()

        for metric in metrics:
            report_metric(metric.category, metric.counter, metric.instance, metric.value)

    def log_altered_network_configuration(self):
        """
        Check various pieces of network configuration and, if altered since the last check, log the new state.
        """
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
