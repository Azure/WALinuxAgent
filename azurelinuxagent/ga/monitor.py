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
    EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=1)
    TELEMETRY_HEARTBEAT_PERIOD = datetime.timedelta(minutes=30)
    # extension metrics period
    CGROUP_TELEMETRY_POLLING_PERIOD = datetime.timedelta(minutes=5)
    CGROUP_TELEMETRY_REPORTING_PERIOD = datetime.timedelta(minutes=30)
    # host plugin
    HOST_PLUGIN_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    HOST_PLUGIN_HEALTH_PERIOD = datetime.timedelta(minutes=5)
    # imds
    IMDS_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    IMDS_HEALTH_PERIOD = datetime.timedelta(minutes=3)

    # Resetting loggers period
    RESET_LOGGERS_PERIOD = datetime.timedelta(hours=12)

    def __init__(self):
        self.osutil = get_osutil()
        self.imds_client = None

        self.event_thread = None
        self.last_reset_loggers_time = None
        self.last_event_collection = None
        self.last_telemetry_heartbeat = None
        self.last_cgroup_polling_telemetry = None
        self.last_cgroup_report_telemetry = None
        self.last_host_plugin_heartbeat = None
        self.last_imds_heartbeat = None
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
            self.event_thread.join()

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
        try:
            if self.last_event_collection is None:
                self.last_event_collection = datetime.datetime.utcnow() - MonitorHandler.EVENT_COLLECTION_PERIOD

            if datetime.datetime.utcnow() >= (self.last_event_collection + MonitorHandler.EVENT_COLLECTION_PERIOD):
                try:
                    event_list = collect_events()

                    if len(event_list.events) > 0:
                        self.protocol.report_event(event_list)
                except Exception as e:
                    logger.warn("{0}", ustr(e))
        except Exception as e:
            logger.warn("Failed to send events: {0}", ustr(e))

        self.last_event_collection = datetime.datetime.utcnow()

    def daemon(self, init_data=False):

        if init_data:
            self.init_protocols()
            self.init_imds_client()

        min_delta = min(MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD,
                        MonitorHandler.CGROUP_TELEMETRY_POLLING_PERIOD,
                        MonitorHandler.CGROUP_TELEMETRY_REPORTING_PERIOD,
                        MonitorHandler.EVENT_COLLECTION_PERIOD,
                        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD,
                        MonitorHandler.IMDS_HEARTBEAT_PERIOD).seconds
        while self.should_run:
            try:
                self.protocol.update_host_plugin_from_goal_state()
                self.send_telemetry_heartbeat()
                self.poll_telemetry_metrics()
                # This will be removed in favor of poll_telemetry_metrics() and it'll directly send the perf data for
                # each cgroup.
                self.send_telemetry_metrics()
                self.collect_and_send_events()
                self.send_host_plugin_heartbeat()
                self.send_imds_heartbeat()
                self.log_altered_network_configuration()
                self.reset_loggers()
            except Exception as e:
                logger.warn("An error occurred in the monitor thread main loop; will skip the current iteration.\n{0}", ustr(e))
            time.sleep(min_delta)

    def reset_loggers(self):
        """
        The loggers maintain hash-tables in memory and they need to be cleaned up from time to time.
        For reference, please check azurelinuxagent.common.logger.Logger and
        azurelinuxagent.common.event.EventLogger classes
        """
        try:
            time_now = datetime.datetime.utcnow()
            if not self.last_reset_loggers_time:
                self.last_reset_loggers_time = time_now

            if time_now >= (self.last_reset_loggers_time + MonitorHandler.RESET_LOGGERS_PERIOD):
                logger.reset_periodic()

        except Exception as e:
            logger.warn("Failed to clear periodic loggers: {0}", ustr(e))

        self.last_reset_loggers_time = time_now

    def send_imds_heartbeat(self):
        """
        Send a health signal every IMDS_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have
        successfully called and validated a response in the last IMDS_HEALTH_PERIOD.
        """

        try:
            if self.last_imds_heartbeat is None:
                self.last_imds_heartbeat = datetime.datetime.utcnow() - MonitorHandler.IMDS_HEARTBEAT_PERIOD

            if datetime.datetime.utcnow() >= (self.last_imds_heartbeat + MonitorHandler.IMDS_HEARTBEAT_PERIOD):
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

        self.last_imds_heartbeat = datetime.datetime.utcnow()

    def send_host_plugin_heartbeat(self):
        """
        Send a health signal every HOST_PLUGIN_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have been able to
        communicate with HostGAPlugin at least once in the last HOST_PLUGIN_HEALTH_PERIOD.
        """
        try:
            if self.last_host_plugin_heartbeat is None:
                self.last_host_plugin_heartbeat = datetime.datetime.utcnow() - MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD

            if datetime.datetime.utcnow() >= (
                self.last_host_plugin_heartbeat + MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD):
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

            self.last_host_plugin_heartbeat = datetime.datetime.utcnow()

    def send_telemetry_heartbeat(self):
        try:
            if self.last_telemetry_heartbeat is None:
                self.last_telemetry_heartbeat = datetime.datetime.utcnow() - MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD

            if datetime.datetime.utcnow() >= (self.last_telemetry_heartbeat + MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD):
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
        except Exception as e:
            logger.warn("Failed to send heartbeat: {0}", ustr(e))

        self.last_telemetry_heartbeat = datetime.datetime.utcnow()

    def poll_telemetry_metrics(self):
        """
        This method polls the tracked cgroups to get data from the cgroups filesystem and send the data directly.

        :return: List of Metrics (which would be sent to PerfCounterMetrics directly.
        """
        try:  # If there is an issue in reporting, it should not take down whole monitor thread.
            time_now = datetime.datetime.utcnow()
            if not self.last_cgroup_polling_telemetry:
                self.last_cgroup_polling_telemetry = time_now

            if time_now >= (self.last_cgroup_polling_telemetry +
                            MonitorHandler.CGROUP_TELEMETRY_POLLING_PERIOD):
                metrics = CGroupsTelemetry.poll_all_tracked()

                if metrics:
                    for metric in metrics:
                        report_metric(metric.category, metric.counter, metric.instance, metric.value)
        except Exception as e:
            logger.warn("Could not poll all the tracked telemetry due to {0}", ustr(e))

        self.last_cgroup_polling_telemetry = datetime.datetime.utcnow()

    def send_telemetry_metrics(self):
        """
        The send_telemetry_metrics would soon be removed in favor of sending performance metrics directly.

        :return:
        """
        try:  # If there is an issue in reporting, it should not take down whole monitor thread.
            time_now = datetime.datetime.utcnow()

            if not self.last_cgroup_report_telemetry:
                self.last_cgroup_report_telemetry = time_now

            if time_now >= (self.last_cgroup_report_telemetry + MonitorHandler.CGROUP_TELEMETRY_REPORTING_PERIOD):
                performance_metrics = CGroupsTelemetry.report_all_tracked()

                if performance_metrics:
                    message = generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                                              performance_metrics=performance_metrics)
                    add_event(name=AGENT_NAME,
                              version=CURRENT_VERSION,
                              op=WALAEventOperation.ExtensionMetricsData,
                              is_success=True,
                              message=ustr(message),
                              log_event=False)
        except Exception as e:
            logger.warn("Could not report all the tracked telemetry due to {0}", ustr(e))

        self.last_cgroup_report_telemetry = datetime.datetime.utcnow()

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
