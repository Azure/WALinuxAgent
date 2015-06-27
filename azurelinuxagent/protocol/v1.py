# Windows Azure Linux Agent
#
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

import os
import json
import re
import time
import traceback
import httplib
import xml.sax.saxutils as saxutils
import xml.etree.ElementTree as ET
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.restutil as restutil

from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
from azurelinuxagent.utils.textutil import *
from azurelinuxagent.protocol.common import *

VersionInfoUri = "http://{0}/?comp=versions"
GoalStateUri = "http://{0}/machine/?comp=goalstate"
HealthReportUri="http://{0}/machine?comp=health"
RolePropUri="http://{0}/machine?comp=roleProperties"
TelemetryUri="http://{0}/machine?comp=telemetrydata"

WireServerAddrFile = "WireServer"
IncarnationFile = "Incarnation"
GoalStateFile = "GoalState.{0}.xml"
HostingEnvFile = "HostingEnvironmentConfig.xml"
SharedConfigFile = "SharedConfig.xml"
CertificatesFile = "Certificates.xml"
CertJsonFile = "Certificates.json"
P7MFile="Certificates.p7m"
PEMFile="Certificates.pem"
ExtensionsConfigFile = "ExtensionsConfig.{0}.xml"
ManifestFile="{0}.{1}.manifest.xml"
TransportCertFile = "TransportCert.pem"
TransportPrivateFile = "TransportPrivate.pem"

ProtocolVersion = "2012-11-30"

class WireProtocolResourceGone(ProtocolError):
    pass

class ProtocolV1(Protocol):
 
    def __init__(self, endpoint):
        self.client = WireClient(endpoint)
   
    def initialize(self):
        self.client.checkWireProtocolVersion()
        self.client.updateGoalState(forced=True)

    def getVmInfo(self):
        hostingEnv = self.client.getHostingEnv()
        vmInfo = VmInfo()
        vmInfo.subscriptionId = None
        vmInfo.vmName = hostingEnv.getVmName()
        return vmInfo

    def getCerts(self):
        certificates = self.client.getCertificates()
        return certificates.getCerts()
       
    def getExtensions(self):
        #Update goal state to get latest extensions config
        self.client.updateGoalState()
        extensionsConfig = self.client.getExtensionsConfig()
        return extensionsConfig.extList
    
    def getExtensionPackages(self, extension):
        goalState = self.client.getGoalState()
        man = self.client.getExtensionManifest(extension, goalState)
        return man.packageList

    def getInstanceMetadata(self):
        goalState = self.client.getGoalState()
        hostingEnv = self.client.getHostingEnv()
        metadata = InstanceMetadata()
        metadata.deploymentName = hostingEnv.getDeploymentName()
        metadata.roleName = hostingEnv.getRoleName()
        metadata.roleInstanceId = goalState.getRoleInstanceId()
        metadata.containerId = goalState.getContainerId()
        return metadata
    
    def reportProvisionStatus(self, provisionStatus):
        validata_param("provisionStatus", provisionStatus, ProvisionStatus)

        if provisionStatus.status is not None:
            self.client.reportHealth(provisionStatus.status, 
                                     provisionStatus.subStatus, 
                                     provisionStatus.description)
        if provisionStatus.properties.certificateThumbprint is not None:
            thumbprint = provisionStatus.properties.certificateThumbprint
            self.client.reportRoleProperties(thumbprint)

    def reportStatus(self, vmStatus):
        validata_param("vmStatus", vmStatus, VMStatus)
        self.client.uploadStatusBlob(vmStatus)

    def reportEvent(self, events):
        validata_param("events", events, TelemetryEventList)
        self.client.reportEvent(events)

def _fetchCache(localFile):
    if not os.path.isfile(localFile):
        raise ProtocolError("{0} is missing.".format(localFile))
    return fileutil.GetFileContents(localFile)

def _fetchUri(uri, headers, chkProxy=False):
    try:
        resp = restutil.HttpGet(uri, headers, chkProxy=chkProxy)
    except restutil.HttpError as e:
        raise ProtocolError(str(e))

    if(resp.status == httplib.GONE):
        raise WireProtocolResourceGone(uri)
    if(resp.status != httplib.OK):
        raise ProtocolError("{0} - {1}".format(resp.status, uri))
    return resp.read()

def _fetchManifest(versionUris):
    for versionUri in versionUris:
        try:
            xmlText = _fetchUri(versionUri.uri, None, chkProxy=True)
            return xmlText
        except IOError, e:
            logger.Warn("Failed to fetch ExtensionManifest: {0}, {1}", e, 
                        versionUri.uri)
    raise ProtocolError("Failed to fetch ExtensionManifest from all sources")

def _buildRoleProperties(containerId, roleInstanceId, thumbprint):
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<RoleProperties>"
            "<Container>"
            "<ContainerId>{0}</ContainerId>"
            "<RoleInstances>"
            "<RoleInstance>"
            "<Id>{1}</Id>"
            "<Properties>"
            "<Property name=\"CertificateThumbprint\" value=\"{2}\" />"
            "</Properties>"
            "</RoleInstance>"
            "</RoleInstances>"
            "</Container>"
            "</RoleProperties>"
            "").format(containerId, roleInstanceId,thumbprint)
    return xml

def _buildHealthReport(incarnation, containerId, roleInstanceId, 
                       status, subStatus, description):
    detail = ''
    if subStatus is not None:
        detail = ("<Details>"
                  "<SubStatus>{0}</SubStatus>"
                  "<Description>{1}</Description>"
                  "</Details>").format(subStatus, description)
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<Health "
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
            " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
            "<GoalStateIncarnation>{0}</GoalStateIncarnation>"
            "<Container>"
            "<ContainerId>{1}</ContainerId>"
            "<RoleInstanceList>"
            "<Role>"
            "<InstanceId>{2}</InstanceId>"
            "<Health>"
            "<State>{3}</State>"
            "{4}"
            "</Health>"
            "</Role>"
            "</RoleInstanceList>"
            "</Container>"
            "</Health>"
            "").format(incarnation,
                       containerId, 
                       roleInstanceId,
                       status, 
                       detail)
    return xml

"""
Convert VMStatus object to status blob format
"""
def vm_agent_status_to_v1(vmAgent):
    formattedMessage = {
        'lang' : 'en-US',
        'message' : vmAgent.message
    }
    guestAgentStatus = {
        'version' : vmAgent.agentVersion,
        'status' : vmAgent.status,
        'formattedMessage' : formattedMessage
    }
    return guestAgentStatus

def extension_substatus_to_v1(substatusList):
    statusList = [] 
    for substatus in substatusList:
        status = {
            "name": substatus.name,
            "status": substatus.status,
            "code": substatus.code,
            "formattedMessage":{
                "lang": "en-US",
                "message": substatus.message
            }
        }
        statusList.append(status)
    return statusList

def extension_handler_status_to_v1(handlerStatus, timestamp):
    if handlerStatus is None or len(handlerStatus.extensionStatusList) == 0:
        return
    extStatus = handlerStatus.extensionStatusList[0]
    substatus = extension_substatus_to_v1(extStatus.substatusList)
    settingsStatus={
        "status":{
            "name": extStatus.name,
            "configurationAppliedTime": extStatus.configurationAppliedTime,
            "operation": extStatus.operation,
            "status": extStatus.status,
            "code": extStatus.code,
            "formattedMessage": {
                "lang":"en-US",
                "message": extStatus.message
            }
        },
        "timestampUTC": timestamp
    }
    
    if len(settingsStatus) == 0:
        settingsStatus['substatus'] = substatus

    handlerAggStatus = {
        'handlerVersion' : handlerStatus.handlerVersion,
        'handlerName' : handlerStatus.handlerName,
        'status' : handlerStatus.status,
        'runtimeSettingsStatus' : {
            'settingsStatus' : settingsStatus,
            'sequenceNumber' : extStatus.sequenceNumber
        }
    }
    return handlerAggStatus


def vm_status_to_v1(vmStatus):
    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    guestAgentStatus = vm_agent_status_to_v1(vmStatus.vmAgent)
    handlerAggStatusList = []
    for extensionHandlerStatus in vmStatus.extensionHandlers:
        handlerAggStatus = extension_handler_status_to_v1(extensionHandlerStatus,
                                                          timestamp)
        handlerAggStatusList.append(handlerAggStatus)

    aggregateStatus = {
        'guestAgentStatus': guestAgentStatus,
        'handlerAggregateStatus' : handlerAggStatusList
    }
    report = {
        'version' : '1.0',
        'timestampUTC' : timestamp,
        'aggregateStatus' : aggregateStatus
    }
    return report


class StatusBlob(object):
    def __init__(self, vmStatus):
        self.vmStatus = vmStatus
    
    def toJson(self):
        report = vm_status_to_v1(self.vmStatus)
        return json.dumps(report)

    __StorageVersion="2014-02-14"

    def upload(self, url):
        logger.Info("Upload status blob")
        blobType = self.getBlobType(url) 
        
        data = self.toJson()
        if blobType == "BlockBlob":
            self.putBlockBlob(url, data)    
        elif blobType == "PageBlob":
            self.putPageBlob(url, data)    
        else:
            raise ProtocolError("Unknown blob type: {0}".format(blobType))

    def getBlobType(self, url):
        #Check blob type
        logger.Verbose("Check blob type.")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        resp = restutil.HttpHead(url, {
            "x-ms-date" :  timestamp,
            'x-ms-version' : self.__class__.__StorageVersion
        });
        if resp is None or resp.status != httplib.OK:
            raise ProtocolError(("Failed to get status blob type: {0}"
                                 "").format(resp.status))

        blobType = resp.getheader("x-ms-blob-type")
        logger.Verbose("Blob type={0}".format(blobType))
        return blobType

    def putBlockBlob(self, url, data):
        logger.Verbose("Upload block blob")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        resp = restutil.HttpPut(url, data, {
            "x-ms-date" :  timestamp,
            "x-ms-blob-type" : "BlockBlob",
            "Content-Length": str(len(data)),
            "x-ms-version" : self.__class__.__StorageVersion
        })
        if resp is None or resp.status != httplib.CREATED:
            raise ProtocolError(("Failed to upload block blob: {0}"
                                 "").format(resp.status))

    def putPageBlob(self, url, data):
        logger.Verbose("Replace old page blob")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        #Align to 512 bytes
        pageBlobSize = ((len(data) + 511) / 512) * 512
        resp = restutil.HttpPut(url, "", {
            "x-ms-date" :  timestamp,
            "x-ms-blob-type" : "PageBlob",
            "Content-Length": "0",
            "x-ms-blob-content-length" : str(pageBlobSize),
            "x-ms-version" : self.__class__.__StorageVersion
        })
        if resp is None or resp.status != httplib.CREATED:
            raise ProtocolError(("Failed to clean up page blob: {0}"
                                 "").format(resp.status))
            
        if '?' in url < 0:
            url = "{0}?comp=page".format(url)
        else:
            url = "{0}&comp=page".format(url)
       
        logger.Verbose("Upload page blob")
        pageMax = 4 * 1024 * 1024 #Max page size: 4MB
        start = 0
        end = 0
        while end < len(data):
            end = min(len(data), start + pageMax)
            contentSize = end - start
            #Align to 512 bytes
            pageEnd = ((end + 511) / 512) * 512
            bufSize = pageEnd - start
            buf = bytearray(bufSize)
            buf[0 : contentSize] = data[start : end]
            resp = restutil.HttpPut(url, buf, {
                "x-ms-date" :  timestamp,
                "x-ms-range" : "bytes={0}-{1}".format(start, pageEnd - 1),
                "x-ms-page-write" : "update",
                "x-ms-version" : self.__class__.__StorageVersion,
                "Content-Length": str(pageEnd - start)
            })
            if resp is None or resp.status != httplib.CREATED:
                raise ProtocolError(("Failed to upload page blob: {0}"
                                     "").format(resp.status))
            start = end

def param_to_xml(param):
    paramFormat = u'<Param Name="{0}" Value={1} T="{2}" />'
    paramType = type(param.value)
    attrType = ""
    if paramType is int:
        attrType = u'mt:uint64'
    elif paramType is str:
        attrType = u'mt:wstr'
    elif str(paramType).count("'unicode'") > 0:
        attrType = u'mt:wstr'
    elif paramType is bool:
        attrType=u'mt:bool'
    elif paramType is float:
        attrType=u'mt:float64'
    return paramFormat.format(param.name, saxutils.quoteattr(str(param.value)),
                              attrType)

def event_to_xml(event):
    params = ""
    for param in event.parameters:
        params += param_to_xml(param)
    eventStr = (u'<Event id="{0}">'
                  u'<![CDATA[{1}]]>'
                u'</Event>').format(event.eventId, params)
    return eventStr

class WireClient(object):
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.goalState = None
        self.updated = None
        self.hostingEnv = None
        self.sharedConfig = None
        self.certificates = None
        self.extensionsConfig = None
        self.requestCount = 0
   
    def updateHostingEnv(self, goalState):
        localFile = HostingEnvFile
        xmlText = _fetchUri(goalState.getHostingEnvUri(), self.getHeader())
        fileutil.SetFileContents(localFile, xmlText)
        self.hostingEnv = HostingEnv(xmlText)
  
    def updateSharedConfig(self, goalState):
        localFile = SharedConfigFile
        xmlText = _fetchUri(goalState.getSharedConfigUri(), self.getHeader())
        fileutil.SetFileContents(localFile, xmlText)
        self.sharedConfig = SharedConfig(xmlText)
    
    def updateCertificates(self, goalState):
        localFile = CertificatesFile
        xmlText = _fetchUri(goalState.getCertificatesUri(), 
                            self.getHeaderWithCert())
        fileutil.SetFileContents(localFile, xmlText)
        self.certificates = Certificates(xmlText)

    def updateExtensionsConfig(self, goalState):
        incarnation = goalState.getIncarnation()
        localFile = ExtensionsConfigFile.format(incarnation)
        xmlText = _fetchUri(goalState.getExtensionsUri(), 
                            self.getHeader())
        fileutil.SetFileContents(localFile, xmlText)
        self.extensionsConfig = ExtensionsConfig(xmlText)
        for extension in self.extensionsConfig.extList.extensions:
            self.updateExtensionManifest(extension, goalState)
    
    def updateExtensionManifest(self, extension, goalState):
        localFile = ManifestFile.format(extension.name, 
                                        goalState.getIncarnation())
        xmlText = _fetchManifest(extension.versionUris)
        fileutil.SetFileContents(localFile, xmlText)

    def updateGoalState(self, forced=False, maxRetry=3):
        uri = GoalStateUri.format(self.endpoint)
        xmlText = _fetchUri(uri, self.getHeader())
        goalState = GoalState(xmlText)
        
        if not forced:
            lastIncarnation = None
            if(os.path.isfile(IncarnationFile)):
                lastIncarnation = fileutil.GetFileContents(IncarnationFile)
            newIncarnation = goalState.getIncarnation()
            if lastIncarnation is not None and lastIncarnation == newIncarnation:
                #Goalstate is not updated.
                return
        
        #Start updating goalstate, retry on 410
        for retry in range(0, maxRetry):
            try:
                self.goalState = goalState
                goalStateFile = GoalStateFile.format(goalState.getIncarnation())
                fileutil.SetFileContents(goalStateFile, xmlText)
                fileutil.SetFileContents(IncarnationFile, 
                                         goalState.getIncarnation())
                self.updateHostingEnv(goalState)
                self.updateSharedConfig(goalState)
                self.updateCertificates(goalState)
                self.updateExtensionsConfig(goalState)
                return
            except WireProtocolResourceGone:
                logger.Info("Incarnation is out of date. Update goalstate.")
                xmlText = _fetchUri(GoalStateUri, self.getHeader())
                goalState = GoalState(xmlText)

        raise ProtocolError("Exceeded max retry updating goal state")
  
    def getGoalState(self):
        if(self.goalState is None):
            incarnation = _fetchCache(IncarnationFile)
            goalStateFile = GoalStateFile.format(incarnation)
            xmlText = _fetchCache(goalStateFile)
            self.goalState = GoalState(xmlText)
        return self.goalState

    def getHostingEnv(self):
        if(self.hostingEnv is None):
            xmlText = _fetchCache(HostingEnvFile)
            self.hostingEnv = HostingEnv(xmlText)
        return self.hostingEnv
    
    def getSharedConfig(self):
        if(self.sharedConfig is None):
            xmlText = _fetchCache(SharedConfigFile)
            self.sharedConfig = SharedConfig(xmlText)
        return self.sharedConfig

    def getCertificates(self):
        if(self.certificates is None):
            xmlText = _fetchCache(Certificates)
            self.certificates = Certificates(xmlText)
        return self.certificates
    
    def getExtensionsConfig(self):
        if(self.extensionsConfig is None):
            goalState = self.getGoalState()
            localFile = ExtensionsConfigFile.format(goalState.getIncarnation())
            xmlText = _fetchCache(localFile)
            self.extensionsConfig = ExtensionsConfig(xmlText)
        return self.extensionsConfig
    
    def getExtensionManifest(self, extension, goalState):
        localFile = ManifestFile.format(extension.name, 
                                        goalState.getIncarnation())
        xmlText = _fetchCache(localFile)
        return ExtensionManifest(xmlText)

    def checkWireProtocolVersion(self):
        uri = VersionInfoUri.format(self.endpoint)
        versionInfoXml = _fetchUri(uri, None)
        self.versionInfo = VersionInfo(versionInfoXml)

        preferred = self.versionInfo.getPreferred()
        if ProtocolVersion == preferred:
            logger.Info("Wire protocol version:{0}", ProtocolVersion)
        elif ProtocolVersion in self.versionInfo.getSupported():
            logger.Info("Wire protocol version:{0}", ProtocolVersion)
            logger.Warn("Server prefered version:{0}", preferred)
        else:
            error = ("Agent supported wire protocol version: {0} was not "
                     "advised by Fabric.").format(ProtocolVersion)
            raise ProtocolNotFound(error)

    def uploadStatusBlob(self, vmStatus):
        extensionsConfig = self.getExtensionsConfig()
        statusBlob = StatusBlob(vmStatus)
        statusBlob.upload(extensionsConfig.getStatusUploadBlob())

    def reportRoleProperties(self, thumbprint):
        goalState = self.getGoalState()
        roleProp = _buildRoleProperties(goalState.getContainerId(),
                                        goalState.getRoleInstanceId(),
                                        thumbprint)
        rolePropUri = RolePropUri.format(self.endpoint)
        ret = restutil.HttpPost(rolePropUri, 
                                roleProp,
                                headers=self.getHeaderWithContentTypeXml())

    
    def reportHealth(self, status, subStatus, description):
        goalState = self.getGoalState()
        healthReport = _buildHealthReport(goalState.getIncarnation(),
                                          goalState.getContainerId(),
                                          goalState.getRoleInstanceId(),
                                          status, 
                                          subStatus, 
                                          description)
        healthReportUri = HealthReportUri.format(self.endpoint)
        headers=self.getHeaderWithContentTypeXml()
        resp = restutil.HttpPost(healthReportUri, 
                                 healthReport,
                                 headers=headers)
    def preventThrottling(self):
        self.requestCount += 1
        if self.requestCount % 3 == 0:
            logger.Info("Sleep 15 before sending event to avoid throttling.")
            self.requestCount = 0
            time.sleep(15)

    def sendEvent(self, providerId, eventStr):
        uri = TelemetryUri.format(self.endpoint)
        dataFormat = (u'<?xml version="1.0"?>'
                      u'<TelemetryData version="1.0">'
                         u'<Provider id="{0}">{1}'
                         u'</Provider>'
                      u'</TelemetryData>')
        data = dataFormat.format(providerId, eventStr)
        try:
            self.preventThrottling()
            resp = restutil.HttpPost(uri, data)
        except restutil.HttpError as e:
            raise ProtocolError("Failed to send events:{0}".format(e))
        
        if resp.status != httplib.OK:
            logger.Verbose(resp.read())
            raise ProtocolError("Failed to send events:{0}".format(resp.status))

    def reportEvent(self, eventList):
        buf = {} 
        #Group events by providerId
        for event in eventList.events:
            if event.providerId not in buf:
                buf[event.providerId] = ""
            eventStr = event_to_xml(event)
            if len(eventStr) >= 63 * 1024:
                logger.Warn("Single event too large: {0}", eventStr[300:])
                continue
            if len(buf[event.providerId] + eventStr) >= 63 * 1024:
                self.sendEvent(event.providerId, buf[event.providerId])
                buf[event.providerId]=""
            buf[event.providerId]=buf[event.providerId] + eventStr

        #Send out all events left in buffer.
        for providerId in buf.keys():
            if len(buf[providerId]) > 0:
                self.sendEvent(providerId, buf[providerId])
                
    def getHeader(self):
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":ProtocolVersion
        }

    def getHeaderWithContentTypeXml(self):
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":ProtocolVersion,
            "Content-Type":"text/xml;charset=utf-8"
        }

    def getHeaderWithCert(self):
        cert = ""
        content = _fetchCache(TransportCertFile)
        for line in content.split('\n'):
            if "CERTIFICATE" not in line:
                cert += line.rstrip()
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":ProtocolVersion,
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert":cert
        }

class VersionInfo(object):
    def __init__(self, xmlText):
        """
        Query endpoint server for wire protocol version.
        Fail if our desired protocol version is not seen.
        """
        logger.Verbose("Load Version.xml")
        self.parse(xmlText)
   
    def parse(self, xmlText):
        xmlDoc = ET.fromstring(xmlText.strip())
        self.preferred = FindFirstNode(xmlDoc, ".//Preferred/Version").text
        logger.Info("Fabric preferred wire protocol version:{0}", self.preferred)

        self.supported = []
        nodes = FindAllNodes(xmlDoc, ".//Supported/Version")
        for node in nodes:
            version = node.text
            logger.Verbose("Fabric supported wire protocol version:{0}", version)
            self.supported.append(version)

    def getPreferred(self):
        return self.preferred

    def getSupported(self):
        return self.supported

 
class GoalState(object):
    
    def __init__(self, xmlText):
        if xmlText is None:
            raise ValueError("GoalState.xml is None")
        logger.Verbose("Load GoalState.xml")
        self.incarnation = None
        self.expectedState = None
        self.hostingEnvUri = None
        self.sharedConfigUri = None
        self.certificatesUri = None
        self.extensionsUri = None
        self.roleInstanceId = None
        self.containerId = None
        self.loadBalancerProbePort = None
        self.parse(xmlText)
        
    def getIncarnation(self):
        return self.incarnation
    
    def getExpectedState(self):
        return self.expectedState
    
    def getHostingEnvUri(self):
        return self.hostingEnvUri
    
    def getSharedConfigUri(self):
        return self.sharedConfigUri
    
    def getCertificatesUri(self):
        return self.certificatesUri

    def getExtensionsUri(self):
        return self.extensionsUri

    def getRoleInstanceId(self):
        return self.roleInstanceId

    def getContainerId(self):
        return self.containerId

    def getLoadBalancerProbePort(self):
        return self.loadBalancerProbePort
   
    def parse(self, xmlText):
        """
        Request configuration data from endpoint server.
        """
        self.xmlText = xmlText
        xmlDoc = ET.fromstring(xmlText.strip())
        self.incarnation = (FindFirstNode(xmlDoc, ".//Incarnation")).text
        self.expectedState = (FindFirstNode(xmlDoc, ".//ExpectedState")).text
        self.hostingEnvUri = (FindFirstNode(xmlDoc, 
                                            ".//HostingEnvironmentConfig")).text
        self.sharedConfigUri = (FindFirstNode(xmlDoc, ".//SharedConfig")).text
        node = (FindFirstNode(xmlDoc, ".//Certificates"))
        self.certificatesUri = node.text if node is not None else None
        self.extensionsUri = (FindFirstNode(xmlDoc, ".//ExtensionsConfig")).text
        self.roleInstanceId = (FindFirstNode(xmlDoc, 
                                             ".//RoleInstance/InstanceId")).text
        self.containerId = (FindFirstNode(xmlDoc, 
                                             ".//Container/ContainerId")).text
        self.loadBalancerProbePort = (FindFirstNode(xmlDoc, 
                                                    ".//LBProbePorts/Port")).text
        return self
        

class HostingEnv(object):
    """
    parse Hosting enviromnet config and store in
    HostingEnvironmentConfig.xml
    """
    def __init__(self, xmlText):
        if xmlText is None:
            raise ValueError("HostingEnvironmentConfig.xml is None")
        logger.Verbose("Load HostingEnvironmentConfig.xml")
        self.parse(xmlText)

    def getVmName(self):
        return self.vmName

    def getRoleName(self):
        return self.roleName

    def getDeploymentName(self):
        return self.deploymentName

    def parse(self, xmlText):
        """
        parse and create HostingEnvironmentConfig.xml.
        """
        self.xmlText = xmlText
        xmlDoc = ET.fromstring(xmlText.strip())
        self.vmName = FindFirstNode(xmlDoc, ".//Incarnation").attrib["instance"]
        self.roleName = FindFirstNode(xmlDoc, ".//Role").attrib["name"]
        deployment = FindFirstNode(xmlDoc, ".//Deployment")
        self.deploymentName = deployment.attrib["name"]
        return self

class SharedConfig(object):
    """
    parse role endpoint server and goal state config.
    """
    def __init__(self, xmlText):
        logger.Verbose("Load SharedConfig.xml")
        self.parse(xmlText)

    def parse(self, xmlText):
        """
        parse and write configuration to file SharedConfig.xml.
        """
        #Not used currently
        return self

class Certificates(object):

    """
    Object containing certificates of host and provisioned user.
    """
    def __init__(self, xmlText=None):
        if xmlText is None:
            raise ValueError("Certificates.xml is None")
        logger.Verbose("Load Certificates.xml")
        self.libDir = OSUtil.GetLibDir()
        self.opensslCmd = OSUtil.GetOpensslCmd()
        self.certs = CertList()
        self.parse(xmlText)

    def parse(self, xmlText):
        """
        Parse multiple certificates into seperate files.
        """
        xmlDoc = ET.fromstring(xmlText.strip())
        dataNode = FindFirstNode(xmlDoc, ".//Data")
        if dataNode is None:
            return 

        p7m = ("MIME-Version:1.0\n"
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(P7MFile, P7MFile, dataNode.text)
        
        fileutil.SetFileContents(os.path.join(self.libDir, P7MFile), p7m)
        #decrypt certificates
        cmd = ("{0} cms -decrypt -in {1} -inkey {2} -recip {3}"
               "| {4} pkcs12 -nodes -password pass: -out {5}"
               "").format(self.opensslCmd, P7MFile, TransportPrivateFile, 
                               TransportCertFile, self.opensslCmd, PEMFile)
        shellutil.Run(cmd)
       
        #The parsing process use public key to match prv and crt.
        #TODO: Is there any way better to do so?
        buf = []
        beginCrt = False
        beginPrv = False
        prvs = {}
        thumbprints = {}
        index = 0
        certs = []
        with open(PEMFile) as pem:
            for line in pem.readlines():
                buf.append(line)
                if re.match(r'[-]+BEGIN.*KEY[-]+', line):
                    beginPrv = True
                elif re.match(r'[-]+BEGIN.*CERTIFICATE[-]+', line):
                    beginCrt = True
                elif re.match(r'[-]+END.*KEY[-]+', line):
                    tmpFile = self.writeToTempFile(index, 'prv', buf)
                    pub = OSUtil.GetPubKeyFromPrv(tmpFile)
                    prvs[pub] = tmpFile
                    buf = []
                    index += 1
                    beginPrv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmpFile = self.writeToTempFile(index, 'crt', buf)
                    pub = OSUtil.GetPubKeyFromCrt(tmpFile)
                    thumbprint = OSUtil.GetThumbprintFromCrt(tmpFile)
                    thumbprints[pub] = thumbprint
                    #Rename crt with thumbprint as the file name 
                    crt = "{0}.crt".format(thumbprint)
                    certs.append({
                        "name":None,
                        "thumbprint":thumbprint
                    })
                    os.rename(tmpFile, os.path.join(self.libDir, crt))
                    buf = []
                    index += 1
                    beginCrt = False

        #Rename prv key with thumbprint as the file name
        for pubkey in prvs:
            thumbprint = thumbprints[pubkey]
            if thumbprint:
                tmpFile = prvs[pubkey]
                prv = "{0}.prv".format(thumbprint)
                os.rename(tmpFile, os.path.join(self.libDir, prv))
                cert = filter(lambda x : x["thumbprint"] == thumbprint, 
                              certs)[0]

        for cert in certs:
            certInfo = Cert()
            set_properties(certInfo, cert)
            self.certs.certificates.append(certInfo)

    def getCerts(self):
        return self.certs

    def writeToTempFile(self, index, suffix, buf):
        fileName = os.path.join(self.libDir, "{0}.{1}".format(index, suffix))
        with open(fileName, 'w') as tmp:
            tmp.writelines(buf)
        return fileName


class ExtensionsConfig(object):
    """
    parse ExtensionsConfig, downloading and unpacking them to /var/lib/waagent.
    Install if <enabled>true</enabled>, remove if it is set to false.
    """

    def __init__(self, xmlText):
        if xmlText is None:
            raise ValueError("ExtensionsConfig is None")
        logger.Verbose("Load ExtensionsConfig.xml")
        self.extList = ExtensionList()
        self.statusUploadBlob = None
        self.parse(xmlText)

    def getStatusUploadBlob(self):
        return self.statusUploadBlob
    
    def parse(self, xmlText):
        """
        Write configuration to file ExtensionsConfig.xml.
        """
        xmlDoc = ET.fromstring(xmlText.strip())
        plugins = FindAllNodes(xmlDoc, ".//Plugins/Plugin")      
        settings = FindAllNodes(xmlDoc, ".//PluginSettings/Plugin")

        for plugin in plugins:
            ext = Extension()
            ext.name = plugin.attrib["name"]
            ext.properties.version = plugin.attrib["version"]
            ext.properties.state = plugin.attrib["state"]

            autoUpgrade = plugin.attrib["autoUpgrade"]
            if autoUpgrade == "true":
                ext.properties.upgradePolicy = "auto"
            else:
                ext.properties.upgradePolicy = "manual"

            location = plugin.attrib["location"]
            failoverLocation = plugin.attrib["failoverlocation"]
            for uri in [location, failoverLocation]:
                versionUri = ExtensionVersionUri() 
                versionUri.uri = uri
                ext.versionUris.append(versionUri)

            name = ext.name
            version = ext.properties.version
            pluginSettings = filter(lambda x: x.attrib["name"] == name 
                                    and x.attrib["version"] == version,
                                    settings)
            if pluginSettings is None or len(pluginSettings) == 0 :
                continue

            runtimeSettings = None
            runtimeSettingsNode = FindFirstNode(pluginSettings[0], 
                                                "RuntimeSettings")
            seqNo = runtimeSettingsNode.attrib["seqNo"]
            runtimeSettingsStr = runtimeSettingsNode.text
            try:
                runtimeSettings = json.loads(runtimeSettingsStr)
            except ValueError as e:
                raise ProtocolError("Invalid extension settings")
            
            for settings in runtimeSettings["runtimeSettings"]:
                hSettings = settings["handlerSettings"]
                extSettings = ExtensionSettings()
                extSettings.sequenceNumber = seqNo
                extSettings.publicSettings = hSettings["publicSettings"]
                extSettings.privateSettings = hSettings["protectedSettings"]
                thumbprint = hSettings["protectedSettingsCertThumbprint"]
                extSettings.certificateThumbprint = thumbprint
                ext.properties.extensions.append(extSettings)

            self.extList.extensions.append(ext)
        self.statusUploadBlob = (FindFirstNode(xmlDoc,"StatusUploadBlob")).text

class ExtensionManifest(object):
    def __init__(self, xmlText):
        if xmlText is None:
            raise ValueError("ExtensionManifest is None")
        logger.Verbose("Load ExtensionManifest.xml")
        self.xmlText = xmlText
        self.packageList = ExtensionPackageList()
        self.parse(xmlText)

    def parse(self, xmlText):
        xmlDoc = ET.fromstring(xmlText.strip())
        packages = FindAllNodes(xmlDoc, ".//Plugin")
        for package in packages:
            version = FindFirstNode(package, "Version").text
            uris = FindAllNodes(package, "Uris/Uri")
            uris = map(lambda x : x.text, uris)
            package = ExtensionPackage() 
            package.version = version
            for uri in uris:
                packageUri = ExtensionPackageUri()
                packageUri.uri = uri
                package.uris.append(packageUri)
            self.packageList.versions.append(package)

