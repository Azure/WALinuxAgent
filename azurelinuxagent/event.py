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
import azurelinuxagent.protocol as prot
from azurelinuxagent.metadata import DistroName, DistroVersion, DistroCodeName,\
                                     GuestAgentVersion
from azurelinuxagent.utils.osutil import OSUtil

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
        self.sysInfo = []
        self.eventDir = os.path.join(OSUtil.GetLibDir(), "events")
        self.initSystemInfo()

    def initSystemInfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(), 
                                                 DistroName,
                                                 DistroVersion,
                                                 DistroCodeName,
                                                 platform.release())
        self.sysInfo.append(prot.TelemetryEventParam("OSVersion", osversion))
        self.sysInfo.append(prot.TelemetryEventParam("GAVersion", 
                                                     GuestAgentVersion))
        self.sysInfo.append(prot.TelemetryEventParam("RAM", 
                                                     OSUtil.GetTotalMemory()))
        self.sysInfo.append(prot.TelemetryEventParam("Processors", 
                                                     OSUtil.GetProcessorCores()))
        protocol = prot.Factory.getDefaultProtocol()
        metadata = protocol.getInstanceMetadata()
        self.sysInfo.append(prot.TelemetryEventParam("TenantName",
                                                     metadata.deploymentName))
        self.sysInfo.append(prot.TelemetryEventParam("RoleName",
                                                     metadata.roleName))
        self.sysInfo.append(prot.TelemetryEventParam("RoleInstanceName",
                                                     metadata.roleInstanceId))
        self.sysInfo.append(prot.TelemetryEventParam("ContainerId",
                                                     metadata.containerId))

    def startEventsLoop(self):
        eventThread = threading.Thread(target = self.eventsLoop)
        eventThread.setDaemon(True)
        eventThread.start()

    def collectEvent(self, eventFilePath):
        try:
            with open(eventFilePath, "rb") as hfile:
            #if fail to open or delete the file, throw exception
                jsonStr = hfile.read().decode("utf-8",'ignore')
            os.remove(eventFilePath)
            return jsonStr
        except IOError as e:
            msg = "Failed to process {0}, {1}".format(eventFilePath, e)
            raise EventError(msg)

    def collectAndSendEvents(self):
        eventList = prot.TelemetryEventList()
        eventFiles = os.listdir(self.eventDir)
        for eventFile in eventFiles:
            if not eventFile.endswith(".tld"):
                continue
            eventFilePath = os.path.join(self.eventDir, eventFile)
            try:
                dataStr = self.collectEvent(eventFilePath)
            except EventError as e:
                logger.Error("{0}", e)
                continue
            try:
                data = json.loads(dataStr)
            except ValueError as e:
                logger.Error("{0}", e)
                continue

            event = prot.TelemetryEvent()
            prot.set_properties(event, data)
            event.parameters.extend(self.sysInfo)
            eventList.events.append(event)
        if len(eventList.events) == 0:
            return

        try:
            protocol = prot.Factory.getDefaultProtocol()
            protocol.reportEvent(eventList)
        except prot.ProtocolError as e:
            logger.Error("{0}", e)

    def eventsLoop(self):
        lastHeatbeat = datetime.datetime.min
        period = datetime.timedelta(hours = 12)
        while(True):
            if (datetime.datetime.now()-lastHeatbeat) > period:
                lastHeatbeat = datetime.datetime.now()
                AddExtensionEvent(op=WALAEventOperation.HeartBeat,
                                  name="WALA",isSuccess=True)
            self.collectAndSendEvents()
            time.sleep(60)
        
def SaveEvent(data):
    eventfolder = os.path.join(OSUtil.GetLibDir(), 'events')
    if not os.path.exists(eventfolder):
        os.mkdir(eventfolder)
        os.chmod(eventfolder,0700)
    if len(os.listdir(eventfolder)) > 1000:
        raise EventError("Too many files under: {0}", eventfolder)

    filename = os.path.join(eventfolder, str(int(time.time()*1000000)))
    try:
        with open(filename+".tmp",'wb+') as hfile:
            hfile.write(data.encode("utf-8"))
        os.rename(filename+".tmp", filename+".tld")
    except IOError as e:
        raise EventError("Failed to write events to file:{0}", e)


def AddExtensionEvent(name, op, isSuccess, duration=0, version="1.0", 
                      message="", evtType="", isInternal=False):
    event = prot.TelemetryEvent(1, "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
    event.parameters.append(prot.TelemetryEventParam('Name', name)) 
    event.parameters.append(prot.TelemetryEventParam('Version', version)) 
    event.parameters.append(prot.TelemetryEventParam('IsInternal', isInternal)) 
    event.parameters.append(prot.TelemetryEventParam('Operation', op)) 
    event.parameters.append(prot.TelemetryEventParam('OperationSuccess', 
                                                     isSuccess)) 
    event.parameters.append(prot.TelemetryEventParam('Message', message)) 
    event.parameters.append(prot.TelemetryEventParam('Duration', duration)) 
    event.parameters.append(prot.TelemetryEventParam('ExtensionType', evtType)) 
    
    data = prot.get_properties(event)
    try:
        SaveEvent(json.dumps(data))
    except EventError as e:
        logger.Error("{0}", e)

def DumpUnhandledError(name):
    if hasattr(sys, 'last_type') and hasattr(sys, 'last_value') and \
            hasattr(sys, 'last_traceback'):
        last_type = getattr(sys, 'last_type')
        last_value = getattr(sys, 'last_value')
        last_traceback = getattr(sys, 'last_traceback')
        error = traceback.format_exception(last_type, last_value, 
                                           last_traceback)
        message= "".join(error)
        logger.Error(message)
        AddExtensionEvent(name, isSuccess=False, message=message,
                          op=WALAEventOperation.UnhandledError)

def EnableUnhandledErrorDump(name):
    atexit.register(DumpUnhandledError, name)

