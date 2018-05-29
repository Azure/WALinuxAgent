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
import time
import threading
import uuid

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.errorstate import ErrorState

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import EventError, ProtocolError, OSUtilError, HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.protocol.restapi import TelemetryEventParam, \
                                                    TelemetryEventList, \
                                                    TelemetryEvent, \
                                                    set_properties
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, getattrib
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, \
            DISTRO_CODE_NAME, AGENT_LONG_VERSION, \
            AGENT_NAME, CURRENT_AGENT, CURRENT_VERSION


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


def get_monitor_handler():
    return MonitorHandler()


class MonitorHandler(object):

    EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=1)
    TELEMETRY_HEARTBEAT_PERIOD = datetime.timedelta(minutes=30)
    HOST_PLUGIN_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    HOST_PLUGIN_HEALTH_PERIOD = datetime.timedelta(minutes=5)

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()
        self.imds_client = get_imds_client()
        self.sysinfo = []
        self.event_thread = None

    def run(self):
        self.init_sysinfo()
        self.start()

    def is_alive(self):
        return self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.setDaemon(True)
        self.event_thread.start()

    def init_sysinfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                 DISTRO_NAME,
                                                 DISTRO_VERSION,
                                                 DISTRO_CODE_NAME,
                                                 platform.release())
        self.sysinfo.append(TelemetryEventParam("OSVersion", osversion))
        self.sysinfo.append(
            TelemetryEventParam("GAVersion", CURRENT_AGENT))

        try:
            ram = self.osutil.get_total_mem()
            processors = self.osutil.get_processor_cores()
            self.sysinfo.append(TelemetryEventParam("RAM", ram))
            self.sysinfo.append(TelemetryEventParam("Processors", processors))
        except OSUtilError as e:
            logger.warn("Failed to get system info: {0}", e)

        try:
            protocol = self.protocol_util.get_protocol()
            vminfo = protocol.get_vminfo()
            self.sysinfo.append(TelemetryEventParam("VMName",
                                                    vminfo.vmName))
            self.sysinfo.append(TelemetryEventParam("TenantName",
                                                    vminfo.tenantName))
            self.sysinfo.append(TelemetryEventParam("RoleName",
                                                    vminfo.roleName))
            self.sysinfo.append(TelemetryEventParam("RoleInstanceName",
                                                    vminfo.roleInstanceName))
            self.sysinfo.append(TelemetryEventParam("ContainerId",
                                                    vminfo.containerId))
        except ProtocolError as e:
            logger.warn("Failed to get system info: {0}", e)

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
                                                    vminfo.image_origin))
        except (HttpError, ValueError) as e:
            logger.warn("failed to get IMDS info: {0}", e)

    def collect_event(self, evt_file_name):
        try:
            logger.verbose("Found event file: {0}", evt_file_name)
            with open(evt_file_name, "rb") as evt_file:
                # if fail to open or delete the file, throw exception
                data_str = evt_file.read().decode("utf-8", 'ignore')
            logger.verbose("Processed event file: {0}", evt_file_name)
            os.remove(evt_file_name)
            return data_str
        except IOError as e:
            msg = "Failed to process {0}, {1}".format(evt_file_name, e)
            raise EventError(msg)

    def collect_and_send_events(self, protocol, last_event_collection):
        if last_event_collection is None:
            last_event_collection = datetime.datetime.utcnow() - MonitorHandler.EVENT_COLLECTION_PERIOD

        if datetime.datetime.utcnow() < (last_event_collection + MonitorHandler.EVENT_COLLECTION_PERIOD):
            return last_event_collection

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
                    logger.error("{0}", e)
                    continue

                try:
                    event = parse_event(data_str)
                    self.add_sysinfo(event)
                    event_list.events.append(event)
                except (ValueError, ProtocolError) as e:
                    logger.warn("Failed to decode event file: {0}", e)
                    continue

            if len(event_list.events) == 0:
                return

            try:
                protocol.report_event(event_list)
            except ProtocolError as e:
                logger.error("{0}", e)
        except Exception as e:
            logger.warn("Failed to send events: {0}", e)

        return datetime.datetime.utcnow()

    def daemon(self):

        # Create a new identifier on each restart, reset the counter and all events
        counter = 0
        last_event_collection = None
        last_telemetry_heartbeat = None
        last_host_plugin_heartbeat = None
        heartbeat_id = str(uuid.uuid4()).upper()
        protocol = self.protocol_util.get_protocol()
        host_plugin_errorstate = ErrorState(min_timedelta=MonitorHandler.HOST_PLUGIN_HEALTH_PERIOD)

        while True:
            last_telemetry_heartbeat = self.send_telemetry_heartbeat(protocol,
                                                                     counter,
                                                                     heartbeat_id,
                                                                     last_telemetry_heartbeat)
            last_event_collection = self.collect_and_send_events(protocol,
                                                                 last_event_collection)
            last_host_plugin_heartbeat = self.send_host_plugin_heartbeat(protocol,
                                                                         last_host_plugin_heartbeat,
                                                                         host_plugin_errorstate)
            time.sleep(5)

    def add_sysinfo(self, event):
        sysinfo_names = [v.name for v in self.sysinfo]
        for param in event.parameters:
            if param.name in sysinfo_names:
                logger.verbose("Remove existing event parameter: [{0}:{1}]",
                               param.name,
                               param.value)
                event.parameters.remove(param)
        event.parameters.extend(self.sysinfo)

    def send_host_plugin_heartbeat(self, protocol, last_host_plugin_heartbeat, host_plugin_errorstate):

        """
        Send a health signal every HOST_PLUGIN_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have been able to
        communicate with HostGAPlugin at least once in the last HOST_PLUGIN_HEALTH_PERIOD.
        """

        if last_host_plugin_heartbeat is None:
            last_host_plugin_heartbeat = datetime.datetime.utcnow() - MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD

        if datetime.datetime.utcnow() < (last_host_plugin_heartbeat + MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD):
            return last_host_plugin_heartbeat

        try:
            host_plugin = protocol.client.get_host_plugin()
            host_plugin.ensure_initialized()
            is_currently_healthy = host_plugin.get_health()

            if is_currently_healthy:
                host_plugin_errorstate.reset()
            else:
                host_plugin_errorstate.incr()

            is_healthy = host_plugin_errorstate.is_triggered() is False

            # TODO: send healthstore signal
            logger.info("HostGAPlugin health: {0}", is_healthy)

        except Exception as e:
            logger.error("Could not send host plugin heartbeat: {0}", ustr(e))

        return datetime.datetime.utcnow()

    def send_telemetry_heartbeat(self, protocol, counter, heartbeat_id, last_telemetry_heartbeat):

        if last_telemetry_heartbeat is None:
            last_telemetry_heartbeat = datetime.datetime.utcnow() - MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD

        if datetime.datetime.utcnow() < (last_telemetry_heartbeat + MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD):
            return last_telemetry_heartbeat

        incarnation = protocol.get_incarnation()
        dropped_packets = self.osutil.get_firewall_dropped_packets(protocol.endpoint)
        msg = "{0};{1};{2};{3}".format(incarnation, counter, heartbeat_id, dropped_packets)

        add_event(
            name=AGENT_NAME,
            version=CURRENT_VERSION,
            op=WALAEventOperation.HeartBeat,
            is_success=True,
            message=msg,
            log_event=False)

        counter += 1

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

        return datetime.datetime.utcnow()
