# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import datetime
import json
import os
import platform
import time
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import EventError, ProtocolError, OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.restapi import TelemetryEventParam, \
                                                    TelemetryEventList, \
                                                    TelemetryEvent, \
                                                    set_properties
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
    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()
        self.sysinfo = []

    def run(self):
        self.init_sysinfo()

        event_thread = threading.Thread(target=self.daemon)
        event_thread.setDaemon(True)
        event_thread.start()

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

    def collect_and_send_events(self):
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
            protocol = self.protocol_util.get_protocol()
            protocol.report_event(event_list)
        except ProtocolError as e:
            logger.error("{0}", e)

    def daemon(self):
        period = datetime.timedelta(minutes=30)
        last_heartbeat = datetime.datetime.utcnow() - period
        while True:
            if datetime.datetime.utcnow() >= (last_heartbeat + period):
                last_heartbeat = datetime.datetime.utcnow()
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.HeartBeat,
                    is_success=True)
            try:
                self.collect_and_send_events()
            except Exception as e:
                logger.warn("Failed to send events: {0}", e)
            time.sleep(60)

    def add_sysinfo(self, event):
        sysinfo_names = [v.name for v in self.sysinfo]
        for param in event.parameters:
            if param.name in sysinfo_names:
                logger.verbose("Remove existing event parameter: [{0}:{1}]",
                               param.name,
                               param.value)
                event.parameters.remove(param)
        event.parameters.extend(self.sysinfo)
