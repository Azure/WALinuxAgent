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
import xml.etree.ElementTree as ET
import walinuxagent.logger as logger
import walinuxagent.utils.restutil as restutil
import walinuxagent.utils.osutil as osutil
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.utils.shellutil as shellutil
from walinuxagent.utils.textutil import *
from walinuxagent.protocol.common import *

WireServerAddrFile = "WireServer"
VersionVersionUri = "http://{0}/?comp=versions"
VersionInfoFile = "Versions.xml"
GoalStateUri = "http://{0}/machine/?comp=goalstate"
GoalStateFile = "GoalState.{0}.xml"
HostingEnvFile = "HostingEnvironmentConfig.xml"
SharedConfigFile = "SharedConfig.xml"
CertificatesFile = "Certificates.xml"
ExtensionsFile = "ExtensionsConfig.{0}.xml"
TransportCertFile = "TransportCert.pem"
TransportPrivateFile = "TransportPrivate.pem"
P7MFile="Certificates.p7m"
PEMFile="Certificates.pem"

ProtocolVersion = "2012-11-30"

class ProtocolV1(Protocol):

    @staticmethod
    def Detect():
        macAddress = osutil.GetMacAddress()
        req = BuildDhcpRequest(macAddress)
        resp = SendDhcpRequest(req)

        if not ValidateDhcpResponse(req, reps):
            return False

        endpoint, gateway, routes = parseDhcpResponse(resp)
#TODO set gateway and routes
        if endpoint:
            fileutil.SetFileContents(__WireServerAddrFile, endpoint)
            return True
        else:
            return False

    @staticmethod
    def Init():
        endpoint = fileutil.GetFileContents(__WireServerAddrFile)
        return ProtocolV1(endpoint)

    def __init__(self, endpoint):
        self.endpoint = endpoint

    def _checkProtocolVersion(self):
        negotiated = None;
        if ProtocolVersion == self.versionInfo.getPreferred():
            negotiated = self.versionInfo.getPreferred()
        for version in self.getSupported():
            if ProtocolVersion == version:
                negotiated = version
                break
        if negotiated:
            logger.Info("Negotiated wire protocol version:{0}", ProtocolVersion)
        else:
            logger.Warn("Agent supported wire protocol version: {0} was not "
                        "advised by Fabric.", ProtocolVersion)

    def refreshCache(self):
        """
        Force the cached data to refresh
        """
        versionInfoXml = restutil.HttpGet(__VersionInfoUri.format(endpoint))
        self.versionInfo = VersionInfo(versionInfoXml)
        fileutil.SetFileContents(__VersionInfoFile, versionInfoXml)

        self._checkProtocolVersion()

        incarnation = self.incarnation if self.incarnation else 0
        goalStateXml = restutil.HttpGet(__GoalStateUri.format(endpoint, 
                                                              incarnation))
        self.goalState = GoalState(goalStateXml)
        self.incarnation = self.goalState.getIncarnation()
        goalStateFile = __GoalStateFile.format(self.incarnation)
        fileutil.SetFileContents(goalStateFile, goalStateXml)

        hostingEnvXml = restutil.HttpGet(self.goalState.getHostingEnvUri())
        self.hostingEnv = HostingEnv(hostingEnvXml)
        fileutil.SetFileContents(__HostingEnvFile, hostingEnvXml)

        sharedConfigXml = restutil.HttpGet(self.goalState.getSharedConfigUri())
        self.shareConfig = ShareConfig(sharedConfigXml)
        fileutil.SetFileContents(__SharedConfigFile, sharedConfigXml)

        certificatesXml = restutil.HttpGet(self.goalState.getCertificatesUri())
        self.certificates = Certificates(certificatesXml)
        fileutil.SetFileContents(__CertificatesFile, certificatesXml)

        extentionsXml = restutil.HttpGet(self.goalState.getExtensionsUri())
        self.extensions = Extensions(extentionsXml)
        extensionsFile = __ExtensionsFile.format(self.incarnation)
        fileutil.SetFileContents(extensionsFile, extentionsXml)

    def getVmInfo(self):
        return self.goalState.getVmInfo()

    def getCerts(self):
        return self.certificates.getCerts()

    def getExtensions(self):
        return self.extensions.getExtensions()

    def reportProvisionStatus(self):
        pass

    def reportAgentStatus(self):
        pass

    def reportExtensionStatus(self):
        pass

    def reportEvent(self):
        pass


def ValidateDhcpResponse(request, response):
    bytesReceived = len(response)
    if bytesReceived < 0xF6:
        logger.Error("HandleDhcpResponse: Too few bytes received:{0}", 
                     str(bytesReceived))
        return False

    logger.Verbose("BytesReceived:{0}", hex(bytesReceived))
    logger.Verbose("DHCP response:{0}", HexDump(response, bytesReceived))

    # check transactionId, cookie, MAC address cookie should never mismatch
    # transactionId and MAC address may mismatch if we see a response 
    # meant from another machine
    if CompareBytes(request, response, 0xEC, 4):
        logger.Verbose("Cookie not match:\nsend={0},\nreceive={1}", 
                       self.HexDump3(request, 0xEC, 4),
                       self.HexDump3(response, 0xEC, 4))
        return False

    if CompareBytes(request, response, 4, 4):
        logger.Verbose("TransactionID not match:\nsend={0},\nreceive={1}", 
                       self.HexDump3(request, 4, 4),
                       self.HexDump3(response, 4, 4))
        return False

    if CompareBytes(request, response, 0x1C, 6):
        logger.Verbose("Mac Address not match:\nsend={0},\nreceive={1}", 
                       self.HexDump3(request, 0x1C, 6),
                       self.HexDump3(response, 0x1C, 6))
        return False

    return True

def parseRoute(response, option, i, length, bytesReceived):
    # http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
    logger.Verbose("Routes at offset: {0} with length:{1}", 
                   hex(i), 
                   hex(length))
    routes = []
    if length < 5:
        logger.Error("Data too small for option:{0}", str(option))
    j = i + 2
    while j < (i + length + 2):
        maskLengthBits = Ord(response[j])
        maskLengthBytes = (((maskLengthBits + 7) & ~7) >> 3)
        mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - maskLengthBits))
        j += 1
        net = UnpackBigEndian(response, j, maskLengthBytes)
        net <<= (32 - maskLengthBytes * 8)
        net &= mask
        j += maskLengthBytes
        gateway = UnpackBigEndian(response, j, 4)
        j += 4
        routes.append((net, mask, gateway))
    if j != (i + length + 2):
        logger.Error("Unable to parse routes")
    return routes

def parseIpAddress(response, option, i, length, bytesReceived):
    if i + 5 < bytesReceived:
        if length != 4:
            logger.Error("Endpoint or Default Gateway not 4 bytes")
            return None
        addr = UnpackBigEndian(response, i + 2, 4)
        IpAddress = IntegerToIpAddressV4String(addr)
        return IpAddress
    else:
        logger.Error("Data too small for option:{0}", str(option))
    return None

def parseDhcpResponse(response):
    """
    parse DHCP response:
    Returns endpoint server or None on error.
    """
    logger.Verbose("parse Dhcp Response")
    bytesReceived = len(response)
    endpoint = None
    gateway = None
    routes = None

    # Walk all the returned options, parsing out what we need, ignoring the 
    # others. We need the custom option 245 to find the the endpoint we talk to,
    # as well as, to handle some Linux DHCP client incompatibilities,
    # options 3 for default gateway and 249 for routes. And 255 is end.

    i = 0xF0 # offset to first option
    while i < bytesReceived:
        option = Ord(response[i])
        length = 0
        if (i + 1) < bytesReceived:
            length = Ord(response[i + 1])
        logger.Verbose("DHCP option {0} at offset:{1} with length:{2}",
                       hex(option), 
                       hex(i), 
                       hex(length))
        if option == 255:
            logger.Verbose("DHCP packet ended at offset:{0}", hex(i))
            break
        elif option == 249:
            routes = parseRoute(response, option, i, length, bytesReceived)
        elif option == 3:
            gateway = parseIpAddres(response, option, i, length, bytesReceived)
            logger.Verbose("Default gateway:{0}, at {1}",
                           gateway, 
                           hex(i))
        elif option == 245:
            endpoint = parseIpAddres(response, option, i, length, bytesReceived)
            logger.Verbose("Azure wire protocol endpoint:{0}, at {1}",
                           gateway, 
                           hex(i))
        else:
            logger.Verbose("Skipping DHCP option:{0} at {1} with length {2}",
                           hex(option),
                           hex(i),
                           hex(length))
        i += length + 2
    return endpoint, gateway, routes


def AllowBroadcastForDhcp(func):
    """
    Temporary allow broadcase for dhcp. Remove the route when done.
    """
    def Wrapper():
        routeAdded = SetBroadcastRouteForDhcp()
        func(*args, **kwargs)
        if routeAdded:
            RemoveBroadcastRouteForDhcp()
    return Wrapper

def DisableDhcpServiceIfNeeded(func):
    """
    In some distros, dhcp service needs to be shutdown before agent probe
    endpoint through dhcp.
    """
    def Wrapper():
        if osutil.IsDhcpEnabled():
            osutil.StopDhcpService()
            func(*args, **kwargs)
            osutil.StartDhcpService()
        else:
            func(*args, **kwargs)
    return Wrapper

__SleepDuration = [0, 10, 30, 60, 60]

@AllowBroadcastForDhcp
@DisableDhcpServiceIfNeeded
def SendDhcpRequest(request, sleepDuration = __SleepDuration):
    resp = _SendDhcpRequest(request)
    for duration in sleepDuration:
       if resp:
           break
       time.Sleep(duration)
       resp = _SendDhcpRequest(request)
    return resp if resp else None

def _SendDhcpRequest(request):
    sock = None
    try:
        osutil.OpenPortForDhcp()
        sock = socket.socket(socket.AF_INET, 
                             socket.SOCK_DGRAM, 
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 68)) 
        sock.sendto(request, ("<broadcast>", 67))
        sock.settimeout(10)
        logger.Log("Send DHCP request: Setting socket.timeout=10, entering recv")
        response = sock.recv(1024)
        return response
    except Exception, e:
        logger.Error("Failed to send DHCP request: {0}", e)
        return None
    finally:
        if sock:
            sock.close()

def BuildDhcpRequest(macAddress):
    """
    Build DHCP request string.
    """
    #
    # typedef struct _DHCP {
    #     UINT8   Opcode;                    /* op:    BOOTREQUEST or BOOTREPLY */
    #     UINT8   HardwareAddressType;       /* htype: ethernet */
    #     UINT8   HardwareAddressLength;     /* hlen:  6 (48 bit mac address) */
    #     UINT8   Hops;                      /* hops:  0 */
    #     UINT8   TransactionID[4];          /* xid:   random */
    #     UINT8   Seconds[2];                /* secs:  0 */
    #     UINT8   Flags[2];                  /* flags: 0 or 0x8000 for broadcast */
    #     UINT8   ClientIpAddress[4];        /* ciaddr: 0 */
    #     UINT8   YourIpAddress[4];          /* yiaddr: 0 */
    #     UINT8   ServerIpAddress[4];        /* siaddr: 0 */
    #     UINT8   RelayAgentIpAddress[4];    /* giaddr: 0 */
    #     UINT8   ClientHardwareAddress[16]; /* chaddr: 6 byte eth MAC address */
    #     UINT8   ServerName[64];            /* sname:  0 */
    #     UINT8   BootFileName[128];         /* file:   0  */
    #     UINT8   MagicCookie[4];            /*   99  130   83   99 */
    #                                        /* 0x63 0x82 0x53 0x63 */
    #     /* options -- hard code ours */
    #
    #     UINT8 MessageTypeCode;              /* 53 */
    #     UINT8 MessageTypeLength;            /* 1 */
    #     UINT8 MessageType;                  /* 1 for DISCOVER */
    #     UINT8 End;                          /* 255 */
    # } DHCP;
    #

    # tuple of 244 zeros
    # (struct.pack_into would be good here, but requires Python 2.5)
    request = [0] * 244

    transactionID = os.urandom(4)

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3):
        request[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4):
        request[4 + a] = Ord(transactionID[a])

    logger.Verbose("BuildDhcpRequest: transactionId:%s,%04X" % (
                   self.HexDump2(transactionID), 
                   self.UnpackBigEndian(request, 4, 4)))

    # fill in ClientHardwareAddress
    for a in range(0, 6):
        request[0x1C + a] = Ord(macAddress[a])

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8):
        request[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("B", request)

class VersionInfo():
    def __init__(self, xmlText):
        """
        Query endpoint server for wire protocol version.
        Fail if our desired protocol version is not seen.
        """
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

class GoalState():
    """
    """
    
    def __init__(self, xmlText):
        self.parse(xmlText)

    def reinitialize(self):
        self.Incarnation = None # integer
        self.ExpectedState = None # "Started"
        self.HostingEnvUri = None
        self.SharedConfigUri = None
        self.CertificatesUri = None
        self.ExtensionsUri = None
        self.RoleInstanceId = None
        self.ContainerId = None
        self.LoadBalancerProbePort = None # integer, ?list of integers

    def parse(self, xmlText):
        """
        Request configuration data from endpoint server.
        """
        self.reinitialize()
        logger.Verbose(xmlText)
        self.xmlText = xmlText
        xmlDoc = ET.fromstring(xmlText.strip())
        self.Incarnation = (FindFirstNode(xmlDoc, ".//Incarnation")).text
        self.ExpectedState = (FindFirstNode(xmlDoc, ".//ExpectedState")).text
        self.HostingEnvUri = (FindFirstNode(xmlDoc, 
                                            ".//HostingEnvironmentConfig")).text
        self.SharedConfigUri = (FindFirstNode(xmlDoc, ".//SharedConfig")).text
        self.CertificatesUri = (FindFirstNode(xmlDoc, ".//Certificates")).text
        self.ExtensionsUri = (FindFirstNode(xmlDoc, ".//ExtensionsConfig")).text
        self.RoleInstanceId = (FindFirstNode(xmlDoc, 
                                             ".//RoleInstance/InstanceId")).text
        self.ContainerId = (FindFirstNode(xmlDoc, 
                                             ".//Container/ContainerId")).text
        self.LoadBalancerProbePort = (FindFirstNode(xmlDoc, 
                                                    ".//LBProbePorts/Port")).text
        return self
        

class HostingEnvironmentConfig(object):
    """
    parse Hosting enviromnet config and store in
    HostingEnvironmentConfig.xml
    """
    def __init__(self, xmlText):
        self.parse(xmlText)

    def reinitialize(self):
        """
        Reset Members.
        """
        pass

    def parse(self, xmlText):
        """
        parse and create HostingEnvironmentConfig.xml.
        """
        self.reinitialize()
        #Not used currently        
        return self

class SharedConfig(object):
    """
    parse role endpoint server and goal state config.
    """
    def __init__(self, xmlText):
        self.parses(xmlText)

    def reinitialize(self):
        """
        Reset members.
        """
        pass

    def parse(self, xmlText):
        """
        parse and write configuration to file SharedConfig.xml.
        """
        self.reinitialize()
        #Not used currently
        return self

class Certificates(object):

    """
    Object containing certificates of host and provisioned user.
    """
    def __init__(self, xmlText, libDir=osutil.LibDir,
                 opensslCmd = osutil.GetOpensslCmd()):
        self.libDir = libDir
        self.opensslCmd = opensslCmd
        self.xmlText = xmlText
        self.parse(xmlText)

    def reinitialize(self):
        """
        Reset members.
        """
        self.certs = []

    def parse(self, xmlText):
        """
        Parse multiple certificates into seperate files.
        """
        self.reinitialize()
        self.xmlText = self.xmlText
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
                    pub = self.getPubKeyFromPrv(tmpFile)
                    prvs[pub] = tmpFile
                    buf = []
                    index += 1
                    beginPrv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmpFile = self.writeToTempFile(index, 'crt', buf)
                    pub = self.getPubKeyFromCrt(tmpFile)
                    thumbprint = self.getThumbprintFromCrt(tmpFile)
                    thumbprints[pub] = thumbprint
                    #Rename crt with thumbprint as the file name 
                    crt = "{0}.crt".format(thumbprint)
                    certs.append({
                        "name":None,
                        "crt":crt,
                        "prv":None,
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
                cert["prv"] = prv

        for cert in certs:
            self.certs.append(CertInfo(cert))
        return self

    def getCerts(self):
        return self.certs

    def writeToTempFile(self, index, suffix, buf):
        fileName = os.path.join(self.libDir, "{0}.{1}".format(index, suffix))
        with open(fileName, 'w') as tmp:
            tmp.writelines(buf)
        return fileName

    def getPubKeyFromPrv(self, fileName):
        cmd = "{0} rsa -in {1} -pubout 2>/dev/null".format(self.opensslCmd, 
                                                           fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def getPubKeyFromCrt(self, fileName):
        cmd = "{0} x509 -in {1} -pubkey -noout".format(self.opensslCmd, 
                                                       fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def getThumbprintFromCrt(self, fileName):
        cmd = "{0} x509 -in {1} -fingerprint -noout".format(self.opensslCmd, 
                                                            fileName)
        thumbprint = shellutil.RunGetOutput(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint

class ExtensionsConfig(object):
    """
    parse ExtensionsConfig, downloading and unpacking them to /var/lib/waagent.
    Install if <enabled>true</enabled>, remove if it is set to false.
    """

    def __init__(self, xmlText):
        self.parse(xmlText)

    def reinitialize(self):
        """
        Reset members.
        """
        self.Extensions = None
        self.StatusUploadBlob = None

    def parse(self, xmlText):
        """
        Write configuration to file ExtensionsConfig.xml.
        """
        self.reinitialize()
        logger.Verbose("Extensions Config: {0}", xmlText)
        xmlDoc = ET.fromstring(xmlText.strip())
        extensions = FindAllNodes(xmlDoc, ".//Plugins/Plugin")      
        settings = FindAllNodes(xmlDoc, ".//PluginSettings/Plugin")
        
        data = []
        for extension in extensions:
            ext = {}
            properties = {}
            runtimeSettings = {}
            handlerSettings = {}

            name = extension.attrib["name"]
            version = extension.attrib["version"]
            location = extension.attrib["location"]
            failoverLocation = extension.attrib["failoverlocation"]
            autoUpgrade = extension.attrib["autoUpgrade"]
            upgradePolicy = "auto" if autoUpgrade == "true" else None
            state = extension.attrib["state"]
            setting = filter(lambda x: x.attrib["name"] == name 
                             and x.attrib["version"] == version,
                             settings)
            runtimeSettingsNode = FindFirstNode(settings[0], ("RuntimeSettings"))
            seqNo = runtimeSettingsNode.attrib["seqNo"]
            runtimeSettingsStr = runtimeSettingsNode.text
            runtimeSettingsDataList = json.loads(runtimeSettingsStr)
            runtimeSettingsData = runtimeSettingsDataList["runtimeSettings"][0]
            handlerSettingsData = runtimeSettingsData["handlerSettings"]
            publicSettings = handlerSettingsData["publicSettings"]
            privateSettings = handlerSettingsData["protectedSettings"]
            thumbprint = handlerSettingsData["protectedSettingsCertThumbprint"]

            ext["name"] = name
            properties["version"] = version
            properties["versionUris"] = [location, failoverLocation]
            properties["upgrade-policy"] = upgradePolicy
            properties["state"] = state
            handlerSettings["sequenceNumber"] = seqNo
            handlerSettings["publicSettings"] = publicSettings
            handlerSettings["privateSettings"] = privateSettings
            handlerSettings["certificateThumbprint"] = thumbprint

            runtimeSettings["handlerSettings"] = handlerSettings
            properties["runtimeSettings"] = runtimeSettings
            ext["properties"] = properties
            data.append(ExtensionInfo(ext))
        self.Extensions = data 
        self.StatusUploadBlob = (FindFirstNode(xmlDoc,"StatusUploadBlob")).text
        return self


