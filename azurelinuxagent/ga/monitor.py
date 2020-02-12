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
import json
import os
import platform
import threading
import time
import uuid

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.networkutil as networkutil
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.datacontract import set_properties
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import EventLogger
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_metric
from azurelinuxagent.common.exception import EventError, ProtocolError, OSUtilError, HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, TelemetryEventList
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, getattrib, hash_strings
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, \
    DISTRO_CODE_NAME, AGENT_NAME, CURRENT_VERSION, AGENT_EXECUTION_MODE


def parse_event(data_str):
    try:
        return parse_json_event(data_str)
    except ValueError:
        return parse_xml_event(data_str)


def parse_xml_param(param_node):
    name = getattrib(param_node, "Name")
    value_str = getattrib(param_node, "Value")
    attr_type = getattrib(param_node, "T")
    value = value_str
    if attr_type == 'mt:uint64':
        value = int(value_str)
    elif attr_type == 'mt:bool':
        value = bool(value_str)
    elif attr_type == 'mt:float64':
        value = float(value_str)
    return TelemetryEventParam(name, value)


def parse_xml_event(data_str):
    try:
        xml_doc = parse_doc(data_str)
        event_id = getattrib(find(xml_doc, "Event"), 'id')
        provider_id = getattrib(find(xml_doc, "Provider"), 'id')
        event = TelemetryEvent(event_id, provider_id)
        param_nodes = findall(xml_doc, 'Param')
        for param_node in param_nodes:
            event.parameters.append(parse_xml_param(param_node))
        return event
    except Exception as e:
        raise ValueError(ustr(e))


def parse_json_event(data_str):
    data = json.loads(data_str)
    event = TelemetryEvent()
    set_properties("TelemetryEvent", event, data)
    return event


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
        self.protocol_util = get_protocol_util()
        self.imds_client = get_imds_client()

        self.event_thread = None
        self.last_reset_loggers_time = None
        self.last_event_collection = None
        self.last_telemetry_heartbeat = None
        self.last_cgroup_polling_telemetry = None
        self.last_cgroup_report_telemetry = None
        self.last_host_plugin_heartbeat = None
        self.last_imds_heartbeat = None
        self.protocol = None
        self.health_service = None
        self.last_route_table_hash = b''
        self.last_nic_state = {}

        self.counter = 0
        self.sysinfo = []
        self.should_run = True
        self.heartbeat_id = str(uuid.uuid4()).upper()
        self.host_plugin_errorstate = ErrorState(min_timedelta=MonitorHandler.HOST_PLUGIN_HEALTH_PERIOD)
        self.imds_errorstate = ErrorState(min_timedelta=MonitorHandler.IMDS_HEALTH_PERIOD)

    def run(self):
        self.init_protocols()
        self.init_sysinfo()
        self.start()

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.event_thread.join()

    def init_protocols(self):
        self.protocol = self.protocol_util.get_protocol()
        self.health_service = HealthService(self.protocol.endpoint)

    def is_alive(self):
        return self.event_thread is not None and self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.setDaemon(True)
        self.event_thread.setName("MonitorHandler")
        self.event_thread.start()

    def init_sysinfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                 DISTRO_NAME,
                                                 DISTRO_VERSION,
                                                 DISTRO_CODE_NAME,
                                                 platform.release())
        self.sysinfo.append(TelemetryEventParam("OSVersion", osversion))
        self.sysinfo.append(TelemetryEventParam("ExecutionMode", AGENT_EXECUTION_MODE))

        try:
            ram = self.osutil.get_total_mem()
            processors = self.osutil.get_processor_cores()
            self.sysinfo.append(TelemetryEventParam("RAM", int(ram)))
            self.sysinfo.append(TelemetryEventParam("Processors", int(processors)))
        except OSUtilError as e:
            logger.warn("Failed to get system info: {0}", ustr(e))

        try:
            vminfo = self.protocol.get_vminfo()
            self.sysinfo.append(TelemetryEventParam("VMName",
                                                    vminfo.vmName))
            self.sysinfo.append(TelemetryEventParam("TenantName",
                                                    vminfo.tenantName))
            self.sysinfo.append(TelemetryEventParam("RoleName",
                                                    vminfo.roleName))
            self.sysinfo.append(TelemetryEventParam("RoleInstanceName",
                                                    vminfo.roleInstanceName))
        except ProtocolError as e:
            logger.warn("Failed to get system info: {0}", ustr(e))

        try:
            vminfo = self.imds_client.get_compute()
            self.sysinfo.append(TelemetryEventParam('Location',
                                                    vminfo.location))
            self.sysinfo.append(TelemetryEventParam('SubscriptionId',
                                                    vminfo.subscriptionId))
            self.sysinfo.append(TelemetryEventParam('ResourceGroupName',
                                                    vminfo.resourceGroupName))
            self.sysinfo.append(TelemetryEventParam('VMId',
                                                    vminfo.vmId))
            self.sysinfo.append(TelemetryEventParam('ImageOrigin',
                                                    int(vminfo.image_origin)))
        except (HttpError, ValueError) as e:
            logger.warn("failed to get IMDS info: {0}", ustr(e))

    @staticmethod
    def collect_event(evt_file_name):
        try:
            logger.verbose("Found event file: {0}", evt_file_name)
            with open(evt_file_name, "rb") as evt_file:
                # if fail to open or delete the file, throw exception
                data_str = evt_file.read().decode("utf-8")
            logger.verbose("Processed event file: {0}", evt_file_name)
            os.remove(evt_file_name)
            return data_str
        except (IOError, OSError, UnicodeDecodeError) as e:
            os.remove(evt_file_name)
            msg = "Failed to process {0}, {1}".format(evt_file_name, e)
            raise EventError(msg)

    def collect_and_send_events(self):
        """
        Periodically read, parse, and send events located in the events folder. Currently, this is done every minute.
        Any .tld file dropped in the events folder will be emitted. These event files can be created either by the
        agent or the extensions. We don't have control over extension's events parameters, but we will override
        any values they might have set for sys_info parameters.
        """
        if self.last_event_collection is None:
            self.last_event_collection = datetime.datetime.utcnow() - MonitorHandler.EVENT_COLLECTION_PERIOD

        if datetime.datetime.utcnow() >= (self.last_event_collection + MonitorHandler.EVENT_COLLECTION_PERIOD):
            try:
                event_list = TelemetryEventList()
                event_dir = os.path.join(conf.get_lib_dir(), "events")
                event_files = os.listdir(event_dir)
                for event_file in event_files:
                    if not event_file.endswith(".tld"):
                        continue
                    event_file_path = os.path.join(event_dir, event_file)
                    try:
                        data_str = self.collect_event(event_file_path)
                    except EventError as e:
                        logger.error("{0}", ustr(e))
                        continue

                    try:
                        event = parse_event(data_str)
                        self.add_sysinfo(event)
                        event_list.events.append(event)
                    except (ValueError, ProtocolError) as e:
                        logger.warn("Failed to decode event file: {0}", ustr(e))
                        continue

                if len(event_list.events) == 0:
                    return

                try:
                    self.protocol.report_event(event_list)
                except ProtocolError as e:
                    logger.error("{0}", ustr(e))
            except Exception as e:
                logger.warn("Failed to send events: {0}", ustr(e))

            self.last_event_collection = datetime.datetime.utcnow()

    def daemon(self):
        min_delta = min(MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD,
                        MonitorHandler.CGROUP_TELEMETRY_POLLING_PERIOD,
                        MonitorHandler.CGROUP_TELEMETRY_REPORTING_PERIOD,
                        MonitorHandler.EVENT_COLLECTION_PERIOD,
                        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD,
                        MonitorHandler.IMDS_HEARTBEAT_PERIOD).seconds
        while self.should_run:
            self.send_telemetry_heartbeat()
            self.poll_telemetry_metrics()
            self.send_telemetry_metrics()   # This will be removed in favor of poll_telemetry_metrics() and it'll directly send the perf data for each cgroup.
            self.collect_and_send_events()
            self.send_host_plugin_heartbeat()
            self.send_imds_heartbeat()
            self.log_altered_network_configuration()
            self.reset_loggers()
            time.sleep(min_delta)

    def reset_loggers(self):
        """
        The loggers maintain hash-tables in memory and they need to be cleaned up from time to time.
        For reference, please check azurelinuxagent.common.logger.Logger and
        azurelinuxagent.common.event.EventLogger classes
        """
        time_now = datetime.datetime.utcnow()
        if not self.last_reset_loggers_time:
            self.last_reset_loggers_time = time_now

        if time_now >= (self.last_reset_loggers_time +
                        MonitorHandler.RESET_LOGGERS_PERIOD):
            try:
                logger.reset_periodic()
            finally:
                self.last_reset_loggers_time = time_now

    def add_sysinfo(self, event):
        """
        This method is called after parsing the event file in the events folder and before emitting it. This means
        all events, either coming from the agent or from the extensions, are passed through this method. The purpose
        is to add a static list of sys_info parameters such as VMName, Region, RAM, etc. If the sys_info parameters
        are already populated in the event, they will be overwritten by the sys_info values obtained from the agent.
        Since the ContainerId parameter is only populated on the fly for the agent events because it is not a static
        sys_info parameter, an event coming from an extension will not have it, so we explicitly add it.
        :param event: Event to be enriched with sys_info parameters
        :return: Event with all parameters added, ready to be reported
        """
        sysinfo_names = [v.name for v in self.sysinfo]
        final_parameters = []

        for param in event.parameters:
            # Discard any sys_info parameters already in the event, since they will be overwritten
            if param.name in sysinfo_names:
                continue
            final_parameters.append(param)

        # Add sys_info params populated by the agent
        final_parameters.extend(self.sysinfo)
        final_parameters = EventLogger.add_default_parameters_to_event(final_parameters, set_values_for_agent=False)

        event.parameters = final_parameters

    def send_imds_heartbeat(self):
        """
        Send a health signal every IMDS_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have
        successfully called and validated a response in the last IMDS_HEALTH_PERIOD.
        """

        if self.last_imds_heartbeat is None:
            self.last_imds_heartbeat = datetime.datetime.utcnow() - MonitorHandler.IMDS_HEARTBEAT_PERIOD

        if datetime.datetime.utcnow() >= (self.last_imds_heartbeat + MonitorHandler.IMDS_HEARTBEAT_PERIOD):
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

            self.last_imds_heartbeat = datetime.datetime.utcnow()

    def send_host_plugin_heartbeat(self):
        """
        Send a health signal every HOST_PLUGIN_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have been able to
        communicate with HostGAPlugin at least once in the last HOST_PLUGIN_HEALTH_PERIOD.
        """
        if self.last_host_plugin_heartbeat is None:
            self.last_host_plugin_heartbeat = datetime.datetime.utcnow() - MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD

        if datetime.datetime.utcnow() >= (
                self.last_host_plugin_heartbeat + MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD):
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

            self.last_host_plugin_heartbeat = datetime.datetime.utcnow()

    def send_telemetry_heartbeat(self):

        if self.last_telemetry_heartbeat is None:
            self.last_telemetry_heartbeat = datetime.datetime.utcnow() - MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD

        if datetime.datetime.utcnow() >= (self.last_telemetry_heartbeat + MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD):
            try:
                incarnation = self.protocol.get_incarnation()
                dropped_packets = self.osutil.get_firewall_dropped_packets(self.protocol.endpoint)
                msg = "{0};{1};{2};{3}".format(incarnation, self.counter, self.heartbeat_id, dropped_packets)

                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.HeartBeat,
                    is_success=True,
                    message=msg,
                    log_event=False)

                self.counter += 1

                io_errors = IOErrorCounter.get_and_reset()
                hostplugin_errors = io_errors.get("hostplugin")
                protocol_errors = io_errors.get("protocol")
                other_errors = io_errors.get("other")

                if hostplugin_errors > 0 or protocol_errors > 0 or other_errors > 0:
                    msg = "hostplugin:{0};protocol:{1};other:{2}".format(hostplugin_errors,
                                                                         protocol_errors,
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
                self.last_cgroup_polling_telemetry = time_now

                if metrics:
                    for metric in metrics:
                        report_metric(metric.category, metric.counter, metric.instance, metric.value)
        except Exception as e:
            logger.warn("Could not poll all the tracked telemetry due to {0}", ustr(e))

    def send_telemetry_metrics(self):
        """
        The send_telemetry_metrics would soon be removed in favor of sending performance metrics directly.

        :return:
        """
        time_now = datetime.datetime.utcnow()

        try:  # If there is an issue in reporting, it should not take down whole monitor thread.
            if not self.last_cgroup_report_telemetry:
                self.last_cgroup_report_telemetry = time_now

            if time_now >= (self.last_cgroup_report_telemetry + MonitorHandler.CGROUP_TELEMETRY_REPORTING_PERIOD):
                performance_metrics = CGroupsTelemetry.report_all_tracked()
                self.last_cgroup_report_telemetry = time_now

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
