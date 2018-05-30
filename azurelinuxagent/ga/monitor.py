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
import traceback
import uuid

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.event import report_metric
from azurelinuxagent.common.cgroups import CGroups, CGroupsTelemetry
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
            DISTRO_CODE_NAME, AGENT_NAME, CURRENT_AGENT, CURRENT_VERSION


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
        os_version = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                  DISTRO_NAME,
                                                  DISTRO_VERSION,
                                                  DISTRO_CODE_NAME,
                                                  platform.release())
        self.sysinfo.append(TelemetryEventParam("OSVersion", os_version))
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
            vm_info = protocol.get_vminfo()
            self.sysinfo.append(TelemetryEventParam("VMName",
                                                    vm_info.vmName))
            self.sysinfo.append(TelemetryEventParam("TenantName",
                                                    vm_info.tenantName))
            self.sysinfo.append(TelemetryEventParam("RoleName",
                                                    vm_info.roleName))
            self.sysinfo.append(TelemetryEventParam("RoleInstanceName",
                                                    vm_info.roleInstanceName))
            self.sysinfo.append(TelemetryEventParam("ContainerId",
                                                    vm_info.containerId))
        except ProtocolError as e:
            logger.warn("Failed to get system info: {0}", e)

        try:
            vm_info = self.imds_client.get_compute()
            self.sysinfo.append(TelemetryEventParam('Location',
                                                    vm_info.location))
            self.sysinfo.append(TelemetryEventParam('SubscriptionId',
                                                    vm_info.subscriptionId))
            self.sysinfo.append(TelemetryEventParam('ResourceGroupName',
                                                    vm_info.resourceGroupName))
            self.sysinfo.append(TelemetryEventParam('VMId',
                                                    vm_info.vmId))
            self.sysinfo.append(TelemetryEventParam('ImageOrigin',
                                                    vm_info.image_origin))
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
        protocol = self.protocol_util.get_protocol()

        # heartbeat
        period = datetime.timedelta(minutes=30)
        last_heartbeat = datetime.datetime.utcnow() - period

        # performance counters

        # Track metrics for the roll-up cgroup and for the agent cgroup
        CGroupsTelemetry.track_cgroup(CGroups.for_extension(""))
        if CGroups.is_systemd_manager():
            CGroupsTelemetry.track_systemd_service(AGENT_NAME)
        else:
            CGroupsTelemetry.track_cgroup(CGroups.for_extension(AGENT_NAME))

        # Deliberately wait to collect data until some time has passed to avoid glitching the first sample.
        # If the agent is restarted, we "lose" the usage between the last collected sample and the time of restart.
        collection_period = datetime.timedelta(minutes=5)
        last_collection = datetime.datetime.utcnow()

        # Create a new identifier on each restart and reset the counter
        heartbeat_id = str(uuid.uuid4()).upper()
        counter = 0
        while True:
            try:
                # heartbeat
                if datetime.datetime.utcnow() >= (last_heartbeat + period):
                    last_heartbeat = datetime.datetime.utcnow()
                    incarnation = protocol.get_incarnation()
                    dropped_packets = self.osutil.get_firewall_dropped_packets(
                                                        protocol.endpoint)

                    msg = "{0};{1};{2};{3}".format(
                        incarnation, counter, heartbeat_id, dropped_packets)

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

                    if hostplugin_errors > 0 \
                            or protocol_errors > 0 \
                            or other_errors > 0:

                        msg = "hostplugin:{0};protocol:{1};other:{2}"\
                            .format(hostplugin_errors,
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
                logger.warn("Failed to send heartbeat: {0}", e)

            try:
                # performance counters
                if datetime.datetime.utcnow() >= (last_collection + collection_period):
                    last_collection = datetime.datetime.utcnow()
                    for cgroup_name, metrics in CGroupsTelemetry.collect_all_tracked().items():
                        for metric_group, metric_name, value in metrics:
                            if value > 0:
                                report_metric(metric_group, metric_name, cgroup_name, value)
            except Exception as e:
                logger.warn("Failed to collect performance metrics: {0}", e)
                logger.warn(traceback.format_exc())

            # Look for extension cgroups we're not already tracking and track them
            ext_handlers_list, incarnation = protocol.get_ext_handlers()
            CGroupsTelemetry.update_tracked(ext_handlers_list.extHandlers)

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
