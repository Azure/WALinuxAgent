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
#
import os
import copy
import re
import xml.dom.minidom
import azureguestagent.logger as logger
from azureguestagent.utils.osutil import CurrOSUtil
from azureguestagent.utils.textutil import GetNodeTextData
import azureguestagent.utils.fileutil as fileutil

class VmInfo():
    def getSubscriptionId(self):
        raise NotImplementedError()

    def getVmName(self):
        raise NotImplementedError()

class CertInfo():
    def getName(self):
        raise NotImplementedError()

    def getThumbprint(self):
        raise NotImplementedError()

    def getCrtFile(self):
        raise NotImplementedError()

    def getPrvFile(self):
        raise NotImplementedError()

class ExtensionInfo(object):
    
    def getName(self):
        raise NotImplementedError()

    def getVersion(self):
        raise NotImplementedError()

    def getVersionUris(self):
        raise NotImplementedError()

    def getUpgradePolicy(self):
        raise NotImplementedError()

    def getState(self):
        raise NotImplementedError()

    def getSeqNo(self):
        raise NotImplementedError()

    def getPublicSettings(self):
        raise NotImplementedError()

    def getProtectedSettings(self):
        raise NotImplementedError()

    def getCertificateThumbprint(self):
        raise NotImplementedError()
   
        
OvfFileName="ovf-env.xml"
class OvfEnv(object):
    """
    Read, and process provisioning info from provisioning file OvfEnv.xml
    """
    def __init__(self, xmlText):
        self.parse(xmlText)

    def reinitialize(self):
        """
        Reset members.
        """
        self.WaNs = "http://schemas.microsoft.com/windowsazure"
        self.OvfNs = "http://schemas.dmtf.org/ovf/environment/1"
        self.MajorVersion = 1
        self.MinorVersion = 0
        self.ComputerName = None
        self.UserName = None
        self.UserPassword = None
        self.CustomData = None
        self.DisableSshPasswordAuthentication = True
        self.SshPublicKeys = []
        self.SshKeyPairs = []

    def getMajorVersion(self):
        return self.MajorVersion

    def getMinorVersion(self):
        return self.MinorVersion

    def getComputerName(self):
        return self.ComputerName

    def getUserName(self):
        return self.UserName

    def getUserPassword(self):
        return self.UserPassword

    def clearUserPassword(self):
        self.UserPassword = None

    def getCustomData(self):
        return self.CustomData

    def getDisableSshPasswordAuthentication(self):
        return self.DisableSshPasswordAuthentication

    def getSshPublicKeys(self):
        return self.SshPublicKeys

    def getSshKeyPairs(self):
        return self.SshKeyPairs

    def parse(self, xmlText):
        """
        Parse xml tree, retreiving user and ssh key information.
        Return self.
        """
        self.reinitialize()
        logger.Verbose(xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        if len(dom.getElementsByTagNameNS(self.OvfNs, "Environment")) != 1:
            Error("Unable to parse OVF XML.")
        section = None
        newer = False
        for p in dom.getElementsByTagNameNS(self.WaNs, "ProvisioningSection"):
            for n in p.childNodes:
                if n.localName == "Version":
                    verparts = GetNodeTextData(n).split('.')
                    major = int(verparts[0])
                    minor = int(verparts[1])
                    if major > self.MajorVersion:
                        newer = True
                    if major != self.MajorVersion:
                        break
                    if minor > self.MinorVersion:
                        newer = True
                    section = p
        if newer == True:
            logger.Warn("Newer provisioning configuration detected. "
                    "Please consider updating waagent.")
            if section == None:
                logger.Error("Could not find ProvisioningSection with "
                        "major version={0}", self.MajorVersion)
                return None
        self.ComputerName = GetNodeTextData(section.getElementsByTagNameNS(self.WaNs, "HostName")[0])
        self.UserName = GetNodeTextData(section.getElementsByTagNameNS(self.WaNs, "UserName")[0])
        try:
            self.UserPassword = GetNodeTextData(section.getElementsByTagNameNS(self.WaNs, "UserPassword")[0])
        except:
            pass
        CDSection=None
        CDSection=section.getElementsByTagNameNS(self.WaNs, "CustomData")
        if len(CDSection) > 0 :
            self.CustomData=GetNodeTextData(CDSection[0])
        disableSshPass = section.getElementsByTagNameNS(self.WaNs, "DisableSshPasswordAuthentication")
        if len(disableSshPass) != 0:
            self.DisableSshPasswordAuthentication = (GetNodeTextData(disableSshPass[0]).lower() == "true")
        for pkey in section.getElementsByTagNameNS(self.WaNs, "PublicKey"):
            logger.Verbose(repr(pkey))
            fp = None
            path = None
            for c in pkey.childNodes:
                if c.localName == "Fingerprint":
                    fp = GetNodeTextData(c).upper()
                    logger.Verbose(fp)
                if c.localName == "Path":
                    path = GetNodeTextData(c)
                    logger.Verbose(path)
            self.SshPublicKeys += [[fp, path]]
        for keyp in section.getElementsByTagNameNS(self.WaNs, "KeyPair"):
            fp = None
            path = None
            logger.Verbose(repr(keyp))
            for c in keyp.childNodes:
                if c.localName == "Fingerprint":
                    fp = GetNodeTextData(c).upper()
                    logger.Verbose(fp)
                if c.localName == "Path":
                    path = GetNodeTextData(c)
                    logger.Verbose(path)
            self.SshKeyPairs += [[fp, path]]
        return self

class InstanceMetadata(object):
    def getDeploymentName(self):
        raise NotImplementedError()
        
    def getRoleName(self):
        raise NotImplementedError()
        
    def getRoleInstanceId(self):
        raise NotImplementedError()
        
    def getContainerId(self):
        raise NotImplementedError()

class ProtocolError(Exception):
    pass

class ProtocolNotFound(Exception):
    pass

class Protocol():
    def initialize(self):
        raise NotImplementedError()

    def getVmInfo(self):
        raise NotImplementedError()

    def getCerts(self):
        raise NotImplementedError()

    def getExtensions(self):
        raise NotImplementedError()
    
    def getExtensionVersions(self, name):
        raise NotImplementedError()

    def getInstanceMetadata(self):
        raise NotImplementedError()

    def getOvf(self):
        ovfFilePath = os.path.join(CurrOSUtil.GetLibDir(), OvfFileName)
        if os.path.isfile(ovfFilePath):
            xmlText = fileutil.GetFileContents(ovfFilePath)        
            return OvfEnv(xmlText)
        else:
            return None

    def reportProvisionStatus(self, status, subStatus, description, thumbprint):
        raise NotImplementedError()

    def reportAgentStatus(self, version, status, message):
        raise NotImplementedError()

    def reportExtensionStatus(self, name, version, statusJson):
        raise NotImplementedError()

    def reportEvent(self):
        raise NotImplementedError()

