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
import xml.sax.saxutils
import time
import threading
import platform
import azurelinuxagent.logger as logger
import azurelinuxagent.protocol as prot
from azurelinuxagent.osinfo import CurrOSInfo
from azurelinuxagent.utils.osutil import CurrOSUtil

class EventError(Exception):
    pass

class WALAEvent(object):   
    def __init__(self):
            
        self.providerId=""
        self.eventId=1
        
        self.OpcodeName=""
        self.KeywordName=""
        self.TaskName=""
        self.TenantName=""
        self.RoleName=""
        self.RoleInstanceName=""
        self.ContainerId=""
        self.ExecutionMode="IAAS"
        self.OSVersion=""
        self.GAVersion=""
        self.RAM=0
        self.Processors=0


    def toXml(self):
        streventId=u'<Event id="{0}"/>'.format(self.eventId)
        strproviderId=u'<Provider id="{0}"/>'.format(self.providerId)
        strRecordFormat = u'<Param Name="{0}" Value="{1}" T="{2}" />'
        strRecordNoQuoteFormat = u'<Param Name="{0}" Value={1} T="{2}" />'
        strMtStr=u'mt:wstr'
        strMtUInt64=u'mt:uint64'
        strMtBool=u'mt:bool'
        strMtFloat=u'mt:float64'
        strEvtDta=u""

        for attrName in  self.__dict__:
            if attrName in ["eventId","filedCount","providerId"]:
                continue
            
            attrValue = self.__dict__[attrName]
            attrType = type(attrValue)
            if attrType is int:
                strEvtDta += strRecordFormat.format(attrName, attrValue,
                                                    strMtUInt64)
            elif attrType is str:
                attrValue = xml.sax.saxutils.quoteattr(attrValue)
                strEvtDta += strRecordNoQuoteFormat.format(attrName, attrValue,
                                                           strMtStr)
            elif str(attrType).count("'unicode'") >0 :
                attrValue = xml.sax.saxutils.quoteattr(attrValue)			 
                strEvtDta += strRecordNoQuoteFormat.format(attrName, attrValue,
                                                           strMtStr)
            elif attrType is bool:
                strEvtDta += strRecordFormat.format(attrName, attrValue,
                                                    strMtBool)
            elif attrType is float:
                strEvtDta += strRecordFormat.format(attrName,attrValue,
                                                    strMtFloat)
            else:
                raise EventError(("Event property not supported: {0}:{1}:{2}"
                                  "").format(attrName, attrValue, attType))

        return u"<Data>{0}{1}{2}</Data>".format(strproviderId, streventId,
                                                strEvtDta)

    def save(self):
        eventfolder = os.path.join(CurrOSUtil.GetLibDir(), 'events')
        if not os.path.exists(eventfolder):
            os.mkdir(eventfolder)
            os.chmod(eventfolder,0700)

        if len(os.listdir(eventfolder)) > 1000:
            raise EventError("Too many files under: {0}", eventfolder)
    
        filename = os.path.join(eventfolder, str(int(time.time()*1000000)))
        try:
            with open(filename+".tmp",'wb+') as hfile:
                hfile.write(self.toXml().encode("utf-8"))
            os.rename(filename+".tmp", filename+".tld")
        except IOError as e:
            raise EventError("Failed to write events to file:{0}", e)

class WALAEventOperation:
    HeartBeat="HeartBeat"
    Provision = "Provision"
    Install = "Install"
    UnIsntall = "UnInstall"
    Disable = "Disable"
    Enable = "Enable"
    Download = "Download"
    Upgrade = "Upgrade"
    Update = "Update"           
    ActivateResourceDisk="ActivateResourceDisk"
    UnhandledError="UnhandledError"

class ExtensionEvent(WALAEvent):
    def __init__(self):
        super(WALAEvent, self).__init__()
        self.eventId=1
        self.providerId="69B669B9-4AF8-4C50-BDC4-6006FA76E975"
        self.Name=""
        self.Version=""
        self.IsInternal=False
        self.Operation=""
        self.OperationSuccess=True
        self.ExtensionType=""
        self.Message=""
        self.Duration=0
               		           
class WALAEventMonitor(object):
    def __init__(self, gaVersion=""):
        self.sysInfo={}
        self.eventCount = 0
        self.gaVersion = gaVersion
        self.eventDir = os.path.join(CurrOSUtil.GetLibDir(), "events")
        self.initSystemInfo()

    def initSystemInfo(self):
        osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(), 
                                                 CurrOSInfo[0],
                                                 CurrOSInfo[1], 
                                                 CurrOSInfo[2],
                                                 platform.release())
        self.sysInfo["OSVersion"] = osversion
        self.sysInfo["GAVersion"] = self.gaVersion
        self.sysInfo["RAM"] = CurrOSUtil.GetTotalMemory()
        self.sysInfo["Processors"]= CurrOSUtil.GetProcessorCores()
        protocol = prot.GetDefaultProtocol()
        metadata = protocol.getInstanceMetadata()
        self.sysInfo["TenantName"] = metadata.getDeploymentName()
        self.sysInfo["RoleName"] = metadata.getRoleName() 
        self.sysInfo["RoleInstanceName"] = metadata.getRoleInstanceId()
        self.sysInfo["ContainerId"] = metadata.getContainerId() 

    def startEventsLoop(self):
        eventThread = threading.Thread(target = self.eventsLoop)
        eventThread.setDaemon(True)
        eventThread.start()
        
    def eventsLoop(self):
        lastHeatbeat = datetime.datetime.min
        period = datetime.timedelta(hours = 12)
        while(True):
            try:
                if (datetime.datetime.now()-lastHeatbeat) > period:
                    lastHeatbeat = datetime.datetime.now()
                    AddExtensionEvent(op=WALAEventOperation.HeartBeat,
                                      name="WALA",isSuccess=True)
                self.collectAndSendWALAEvents()
                time.sleep(60)
            except EventError as e:
                logger.Error("{0}", e)
			     		    		
    def sendEvent(self, providerId, events):
        dataFormat = u'<?xml version="1.0"?>\
                       <TelemetryData version="1.0">\
                         <Provider id="{0}">{1}\
                         </Provider>\
                       </TelemetryData>'
        data = dataFormat.format(providerId, events)
        self.eventCount += 1
        if self.eventCount % 3 == 0:
            logger.Info("Sleep 15 before sending event to avoid throttling.")
            self.eventCount = 0
            time.sleep(15)
       
        try:
            protocol = prot.GetDefaultProtocol()
            protocol.reportEvent(data)
        except prot.ProtocolError as e:
            logger.Error("Failed  to send events:{0}", e)
    
    def collectEvent(self, eventFilePath):
        try:
            with open(eventFile, "rb") as hfile:
            #if fail to open or delete the file, throw exception 
                xmlStr = hfile.read().decode("utf-8",'ignore')
            os.remove(eventFilePath)
        except IOError as e:
            raise EventError("Failed to process: {0}".format(e))

        params=""
        eventId=""
        providerId=""
        #if exception happen during process an event, catch it and continue
        try:
            xmlStr = self.addSystemInfo(xmlStr)
            doc = xml.dom.minidom.parseString(xmlStr.encode("utf-8"))
            for node in doc.childNodes[0].childNodes:
                if node.tagName == "Param":
                    params += node.toxml()
                if node.tagName == "Event":
                    eventId = node.getAttribute("id")
                if node.tagName == "Provider":
                    providerId = node.getAttribute("id")
        #TODO do not catch all exception
        except Exception as e:
            raise EventError("Failed to parse event xml: {0}".format(e))

        if len(params)==0:
            raise EventError("Param list is empty.")
        if len(eventId)==0:
            raise EventError("EventId is empty.")
        if len(providerId)==0:
            raise EventError("ProviderId is empty.")

        eventStr = u'<Event id="{0}">\
                       <![CDATA[{1}]]>\
                     </Event>'.format(eventId, params)
        
        if len(eventstr) >= 63*1024:
            raise EventError("Signle event too large abort " + eventstr[:300])

        return providerId, eventStr

    def collectAndSendWALAEvents(self):        
        if not os.path.exists(self.eventDir):
            return
        
        #Buffer events with the same provider id and send out in batch
        buf = {}

        eventFiles = os.listdir(self.eventDir)
        for eventFile in eventFiles:
            if not eventFile.endswith(".tld"):
                continue      

            eventFilePath = os.path.join(self.eventDir, eventFile)
            try:
                eventStr = self.collectEvent(eventFilePath) 
                if not buf.get(providerId):
                    buf[providerId]= ""
                
                #Buffer will exceed max length, send events and clear buffer
                if len(buf.get(providerId) + eventStr)>= 63*1024:
                    self.sendEvent(providerId, buf.get(providerId))
                    buf[providerId]=""

                buf[providerId]=buf.get(providerId) + eventStr

            except EventError as e:
                logger.Warn("Failed to collect event:{0}, {1}", eventFilePath, e)
        
        #Send out all events left in buffer.
        for providerId in buf.keys():
            if len(events[key]) > 0:
                self.sendEvent(providerId, buf[providerId])
                

    def addSystemInfo(self, eventData):
        #TODO why need to encode
        doc = xml.dom.minidom.parseString(eventData.encode("utf-8"))
        eventObject = doc.childNodes[0]
        for node in eventObject.childNodes:
            if node.tagName == "Param":
                name = node.getAttribute("Name")
                if self.sysInfo.get(name):
                    value = xml.sax.saxutils.escape(str(self.sysInfo[name]))
                    node.setAttribute("Value", value)

        return  eventObject.toxml()            

def AddExtensionEvent(name, op, isSuccess, duration=0, version="1.0", 
                      message="", evtType="", isInternal=False):
    event = ExtensionEvent()
    event.Name=name 
    event.Version=version 
    event.IsInternal=isInternal
    event.Operation=op
    event.OperationSuccess=isSuccess
    event.Message=message 
    event.Duration=duration
    event.ExtensionType=evtType
    try:
        event.save()
    except EventError as e:
        logger.Error("{0}", e)

def DumpUnhandledError(name, gaVersion=""):
    if hasattr(sys, 'last_type') and hasattr(sys, 'last_value') and \
            hasattr(sys, 'last_traceback'):
        error = traceback.format_exception(sys.last_type, sys.last_value,
                                           sys.last_traceback)
        message= "".join(error)
        logger.Error(message)
        AddExtensionEvent(name, isSuccess=False, message=message,
                          op=WALAEventOperation.UnhandledError)
        WALAEventMonitor(gaVersion=gaVersion).collectAndSendWALAEvents()


def EnableUnhandledErrorDump(name):
    atexit.register(DumpUnhandledError, name)

