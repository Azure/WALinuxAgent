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
from azurelinuxagent.future import text
import azurelinuxagent.protocol as prot
from azurelinuxagent.metadata import DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_CODE_NAME, AGENT_VERSION
from azurelinuxagent.utils.osutil import OSUTIL

class EventError(Exception):
    pass

class WALAEventOperation:
    HeartBeat="HeartBeat"
    Provision = "Provision"
    Install = "Install"
    UnInstall = "UnInstall"
    Disable = "Disable"
    Enable = "Enable"
    Download = "Download"
    Upgrade = "Upgrade"
    Update = "Update"
    ActivateResourceDisk="ActivateResourceDisk"
    UnhandledError="UnhandledError"

class EventMonitor(object):
    def __init__(self):
        self.sysinfo = []
        self.event_dir = os.path.join(OSUTIL.get_lib_dir(), "events")

    def init_sysinfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                 DISTRO_NAME,
                                                 DISTRO_VERSION,
                                                 DISTRO_CODE_NAME,
                                                 platform.release())

        self.sysinfo.append(prot.TelemetryEventParam("OSVersion", osversion))
        self.sysinfo.append(prot.TelemetryEventParam("GAVersion",
                                                     AGENT_VERSION))
        self.sysinfo.append(prot.TelemetryEventParam("RAM",
                                                     OSUTIL.get_total_mem()))
        self.sysinfo.append(prot.TelemetryEventParam("Processors",
                                                     OSUTIL.get_processor_cores()))
        try:
            protocol = prot.FACTORY.get_default_protocol()
            vminfo = protocol.get_vminfo()
            self.sysinfo.append(prot.TelemetryEventParam("VMName",
                                                         vminfo.vmName))
            #TODO add other system info like, subscription id, etc.
        except prot.ProtocolError as e:
            logger.warn("Failed to get vm info: {0}", e)
       
    def start(self):
        event_thread = threading.Thread(target = self.run)
        event_thread.setDaemon(True)
        event_thread.start()

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
        event_list = prot.TelemetryEventList()
        event_files = os.listdir(self.event_dir)
        for event_file in event_files:
            if not event_file.endswith(".tld"):
                continue
            event_file_path = os.path.join(self.event_dir, event_file)
            try:
                data_str = self.collect_event(event_file_path)
            except EventError as e:
                logger.error("{0}", e)
                continue
            try:
                data = json.loads(data_str)
            except ValueError as e:
                logger.verb(data_str)
                logger.error("Failed to decode json event file: {0}", e)
                continue

            event = prot.TelemetryEvent()
            prot.set_properties("event", event, data)
            event.parameters.extend(self.sysinfo)
            event_list.events.append(event)
        if len(event_list.events) == 0:
            return
        
        try:
            protocol = prot.FACTORY.get_default_protocol()
            protocol.report_event(event_list)
        except prot.ProtocolError as e:
            logger.error("{0}", e)

    def run(self):
        self.init_sysinfo()
        last_heartbeat = datetime.datetime.min
        period = datetime.timedelta(hours = 12)
        while(True):
            if (datetime.datetime.now()-last_heartbeat) > period:
                last_heartbeat = datetime.datetime.now()
                add_event(op=WALAEventOperation.HeartBeat,
                                  name="WALA",is_success=True)
            self.collect_and_send_events()
            time.sleep(60)

def save_event(data):
    event_dir = os.path.join(OSUTIL.get_lib_dir(), 'events')
    if not os.path.exists(event_dir):
        os.mkdir(event_dir)
        os.chmod(event_dir,0o700)
    if len(os.listdir(event_dir)) > 1000:
        raise EventError("Too many files under: {0}", event_dir)

    filename = os.path.join(event_dir, text(int(time.time()*1000000)))
    try:
        with open(filename+".tmp",'wb+') as hfile:
            hfile.write(data.encode("utf-8"))
        os.rename(filename+".tmp", filename+".tld")
    except IOError as e:
        raise EventError("Failed to write events to file:{0}", e)

def add_event(name, op="", is_success=True, duration=0, version="1.0",
              message="", evt_type="", is_internal=False):
    log = logger.info if is_success else logger.error
    log("Event: name={0}, op={1}, message={2}", name, op, message)
    event = prot.TelemetryEvent(1, "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
    event.parameters.append(prot.TelemetryEventParam('Name', name))
    event.parameters.append(prot.TelemetryEventParam('Version', version))
    event.parameters.append(prot.TelemetryEventParam('IsInternal', is_internal))
    event.parameters.append(prot.TelemetryEventParam('Operation', op))
    event.parameters.append(prot.TelemetryEventParam('OperationSuccess',
                                                     is_success))
    event.parameters.append(prot.TelemetryEventParam('Message', message))
    event.parameters.append(prot.TelemetryEventParam('Duration', duration))
    event.parameters.append(prot.TelemetryEventParam('ExtensionType', evt_type))

    data = prot.get_properties(event)
    try:
        save_event(json.dumps(data))
    except EventError as e:
        logger.error("{0}", e)

def dump_unhandled_err(name):
    if hasattr(sys, 'last_type') and hasattr(sys, 'last_value') and \
            hasattr(sys, 'last_traceback'):
        last_type = getattr(sys, 'last_type')
        last_value = getattr(sys, 'last_value')
        last_traceback = getattr(sys, 'last_traceback')
        error = traceback.format_exception(last_type, last_value,
                                           last_traceback)
        message= "".join(error)
        add_event(name, is_success=False, message=message,
                          op=WALAEventOperation.UnhandledError)

def enable_unhandled_err_dump(name):
    atexit.register(dump_unhandled_err, name)

