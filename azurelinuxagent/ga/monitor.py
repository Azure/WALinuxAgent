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
import io
import json
import linecache
import os
import platform
import time
import threading
import traceback

import tracemalloc
import uuid

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

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

        self.tracemalloc_snapshots = []
        self.tracemalloc_filters = [
            tracemalloc.Filter(False, linecache.__file__),
            tracemalloc.Filter(False, tracemalloc.__file__),
        ]

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

    def display_top_stats(self, top_stats, header, limit=50):
        output = io.StringIO()

        output.write(header)
        output.write("\n")
        output.write("Top %s lines\n" % limit)
        for index, stat in enumerate(top_stats[:limit], 1):
            frame = stat.traceback[0]
            # replace "/path/to/module/file.py" with "module/file.py"
            filename = os.sep.join(frame.filename.split(os.sep)[-2:])
            output.write("#%s: %s:%s: %.1f KiB\n"
                  % (index, filename, frame.lineno, stat.size / 1024))
            line = linecache.getline(frame.filename, frame.lineno).strip()
            if line:
                output.write("    %s\n" % line)

        other = top_stats[limit:]
        if other:
            size = sum(stat.size for stat in other)
            output.write("%s other: %.1f KiB\n" % (len(other), size / 1024))
        total = sum(stat.size for stat in top_stats)
        output.write("Total allocated size: %.1f KiB\n" % (total / 1024))

        logger.info(output.getvalue())

    def display_top_stats_diff(self, top_stats, header, limit=50):
        output = io.StringIO()

        output.write(header)
        output.write("\n")
        output.write("Top %s lines\n" % limit)
        for index, stat in enumerate(top_stats[:limit], 1):
            frame = stat.traceback[0]
            # replace "/path/to/module/file.py" with "module/file.py"
            filename = os.sep.join(frame.filename.split(os.sep)[-2:])
            output.write("#%s: %s:%s: total=%.1f KiB, new=%.1f KiB, new blocks=%d, total blocks=%d\n"
                  % (index, filename, frame.lineno, stat.size_diff / 1024, stat.size / 1024, stat.count_diff, stat.count))
            line = linecache.getline(frame.filename, frame.lineno).strip()
            if line:
                output.write("    %s\n" % line)

        other = top_stats[limit:]
        if other:
            size = sum(stat.size for stat in other)
            output.write("%s other: %.1f KiB\n" % (len(other), size / 1024))
        total = sum(stat.size for stat in top_stats)
        output.write("Total allocated size: %.1f KiB\n" % (total / 1024))

        logger.info(output.getvalue())


    def display_top(self, snapshot, key_type='lineno', limit=10):
        snapshot = snapshot.filter_traces(self.tracemalloc_filters)

        top_stats = snapshot.statistics(key_type)
        self.display_top_stats(top_stats, ">>> SNAPSHOT STATISTICS <<<")

    def collect_stats(self):
        snapshot = tracemalloc.take_snapshot()
        self.display_top(snapshot)

        self.tracemalloc_snapshots.append(snapshot)
        if len(self.tracemalloc_snapshots) > 1:
            stats = self.tracemalloc_snapshots[-1].filter_traces(self.tracemalloc_filters).compare_to(self.tracemalloc_snapshots[-2], 'lineno')
            self.display_top_stats_diff(stats, ">>> SNAPSHOT COMPARED TO PREVIOUS STASTISTICS <<<")
            self.tracemalloc_snapshots.pop(0)

    def daemon(self):
        period = datetime.timedelta(minutes=30)
        protocol = self.protocol_util.get_protocol()        
        last_heartbeat = datetime.datetime.utcnow() - period

        # Create a new identifier on each restart and reset the counter
        heartbeat_id = str(uuid.uuid4()).upper()
        counter = 0

        logger.info(">>> ENABLE TRACEMALLOC <<<")
        tracemalloc.start(10)

        try:
            while True:
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

                try:
                    self.collect_and_send_events()
                except Exception as e:
                    logger.warn("Failed to send events: {0}", e)

                self.collect_stats()
                time.sleep(60)
        except:
            logger.error(traceback.format_exc())

    def add_sysinfo(self, event):
        sysinfo_names = [v.name for v in self.sysinfo]
        for param in event.parameters:
            if param.name in sysinfo_names:
                logger.verbose("Remove existing event parameter: [{0}:{1}]",
                               param.name,
                               param.value)
                event.parameters.remove(param)
        event.parameters.extend(self.sysinfo)
