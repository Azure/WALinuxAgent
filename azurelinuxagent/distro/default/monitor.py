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

import os
import sys
import traceback
import atexit
import json
import time
import datetime
import threading
import platform
import azurelinuxagent.logger as logger
from azurelinuxagent.event import WALAEventOperation, add_event
from azurelinuxagent.exception import EventError, ProtocolError, OSUtilError
from azurelinuxagent.future import ustr
from azurelinuxagent.protocol.restapi import TelemetryEventParam, \
                                             TelemetryEventList, \
                                             TelemetryEvent, \
                                             set_properties, get_properties
from azurelinuxagent.metadata import DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_CODE_NAME, AGENT_VERSION



class MonitorHandler(object):
    def __init__(self, distro):
        self.distro = distro
        self.sysinfo = []
  
    def run(self):
        event_thread = threading.Thread(target = self.daemon)
        event_thread.setDaemon(True)
        event_thread.start()

    def init_sysinfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                 DISTRO_NAME,
                                                 DISTRO_VERSION,
                                                 DISTRO_CODE_NAME,
                                                 platform.release())
        

        self.sysinfo.append(TelemetryEventParam("OSVersion", osversion))
        self.sysinfo.append(TelemetryEventParam("GAVersion", AGENT_VERSION))
    
        try:
            ram = self.distro.osutil.get_total_mem()
            processors = self.distro.osutil.get_processor_cores()
            self.sysinfo.append(TelemetryEventParam("RAM", ram))
            self.sysinfo.append(TelemetryEventParam("Processors", processors))
        except OSUtilError as e:
            logger.warn("Failed to get system info: {0}", e)

        try:
            protocol = self.distro.protocol_util.get_protocol()
            vminfo = protocol.get_vminfo()
            #TODO add more system info
            self.sysinfo.append(TelemetryEventParam("VMName", vminfo.vmName ))
        except ProtocolError as e:
            logger.warn("Failed to get system info: {0}", e)

    def collect_event(self, evt_file_name):
        try:
            logger.verb("Found event file: {0}", evt_file_name)
            with open(evt_file_name, "rb") as evt_file:
            #if fail to open or delete the file, throw exception
                json_str = evt_file.read().decode("utf-8",'ignore')
            logger.verb("Processed event file: {0}", evt_file_name)
            os.remove(evt_file_name)
            return json_str
        except IOError as e:
            msg = "Failed to process {0}, {1}".format(evt_file_name, e)
            raise EventError(msg)

    def collect_and_send_events(self):
        event_list = TelemetryEventList()
        event_dir = os.path.join(self.distro.osutil.get_lib_dir(), "event")
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
                data = json.loads(data_str)
            except ValueError as e:
                logger.verb(data_str)
                logger.verb("Failed to decode json event file: {0}", e)
                continue

            event = TelemetryEvent()
            set_properties("event", event, data)
            event.parameters.extend(self.sysinfo)
            event_list.events.append(event)
        if len(event_list.events) == 0:
            return
        
        try:
            protocol = self.distro.protocol_util.get_protocol()
            protocol.report_event(event_list)
        except ProtocolError as e:
            logger.error("{0}", e)

    def daemon(self):
        self.init_sysinfo()
        last_heartbeat = datetime.datetime.min
        period = datetime.timedelta(hours = 12)
        while(True):
            if (datetime.datetime.now()-last_heartbeat) > period:
                last_heartbeat = datetime.datetime.now()
                add_event(op=WALAEventOperation.HeartBeat, name="WALA",
                          is_success=True)
            self.collect_and_send_events()
            time.sleep(60)
