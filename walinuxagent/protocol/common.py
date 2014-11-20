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
import xml.dom.minidom
import walinuxagent.logger as logger
from walinuxagent.utils.osutil import CurrOS
from walinuxagent.utils.textutil import GetNodeTextData
import walinuxagent.utils.fileutil as fileutil

class VmInfo():
    def __init__(self, data):
        self.data = data

    def getSubscriptionId(self):
        return self.data["subscriptionId"]

    def getVmName(self):
        return self.data["vmName"]

class CertInfo():
    def __init__(self, data):
        self.data = data

    def getName(self):
        return self.data["name"]

    def getThumbprint(self):
        return self.data["thumbprint"]

    def getCrtFile(self):
        return self.data["crt"]

    def getPrvFile(self):
        return self.data["prv"]


class ExtensionInfo():
    def __init__(self, data):
        self.data = data
        libDir = CurrOS.GetLibDir()
        baseDirName = "{0}-{1}".format(self.getName(), self.getVersion())
        self.baseDir = os.path.join(libDir, baseDirName) 

    def getBaseDir(self):
        return self.baseDir

    def getStatusDir(self):
        return  os.path.join(self.baseDir, "status")

    def getStatusFile(self):
        return os.path.join(self.getStatusDir(), 
                "{0}.status".format(self.getSeqNo()))

    def getConfigDir(self):
        return os.path.join(self.baseDir, 'config')

    def getSettingsFile(self):
        return os.path.join(self.getConfigDir(), 
                "{0}.settings".format(self.getSeqNo()))

    def getHandlerStateFile(self):
        return os.path.join(self.getConfigDir(), 'HandlerState')

    def getHeartbeatFile(self):
        return os.path.join(self.baseDir, 'heartbeat.log')

    def getManifestFile(self):
        return os.path.join(self.baseDir, 'HandlerManifest.json')

    def getEnvironmentFile(self):
        return os.path.join(self.baseDir, 'HandlerEnvironment.json')

    def getLogDir(self):
        return os.path.join('/var/log/azure',self.getName(), self.getVersion())

    def getName(self):
        return self.data["name"]

    def getVersion(self):
        return self.data["properties"]["version"]

    def getVersionUris(self):
        return self.data["properties"]["versionUris"]

    def getUpgradePolicy(self):
        return self.data["properties"]["upgrade-policy"]

    def getState(self):
        return self.data["properties"]["state"]

    def getSeqNo(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["sequenceNumber"]

    def getSettings(self):
        return {
            'runtimeSettings' : self.data["properties"]['runtimeSettings']
        }

    def getPublicSettings(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["publicSettings"]

    def getProtectedSettings(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["privateSettings"]

    def getCertificateThumbprint(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["certificateThumbprint"]

    def getTargetVersion(self, currVersion):
        if self.getUpgradePolicy().lower() != 'auto':
            return self.getVersion()
        if currVersion is None:
            currVersion = self.getVersion() 
        major = currVersion.split('.')[0]
        if major is None:
            return self.getVersion()

        versionUris = self.getVersionUris()
        if major is not None:
            versionUris = filter(lambda x : x["version"].startswith(major + "."), 
                                 versionUris)
        versionUris = sorted(versionUris, 
                             key=lambda x: x["version"], 
                             reverse=True)
        if len(versionUris) > 0:
            return versionUris[0]
        else:
            raise Exception("Couldn't find correct extension version")

    def getPackageUris(self):
        versionUris = self.getVersionUris()
        version = self.getVersion()
        for versionUri in versionUris:
            if versionUri['version']== version:
                return versionUri['uris']
        return None

    def copy(self, version):
        data = copy.deepcopy(self.data)
        if version is not None:
            data["properties"]["version"] = version
        return ExtensionInfo(data)

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

class Protocol():
    def checkVersion(self):
        pass

    def refreshCache(self):
        pass

    def getVmInfo(self):
        pass

    def getCerts(self):
        pass

    def getExtensions(self):
        pass

    def getOvf(self):
        ovfFilePath = os.path.join(CurrOS.GetLibDir(), OvfFileName)
        if os.path.isfile(ovfFilePath):
            xmlText = fileutil.GetFileContents(ovfFilePath)        
            return OvfEnv(xmlText)
        else:
            return None

    def copyOvf(self):
        """
        Copy ovf env file from dvd to hard disk. 
        Remove password before save it to the disk
        """
        ovfFile = CurrOS.GetOvfEnvPathOnDvd()
        CurrOS.MountDvd()

        if not os.path.isfile(ovfFile):
            raise Exception("Unable to provision: Missing ovf-env.xml on DVD")
        ovfxml = CurrOS.GetFileContents(ovfFile, removeBom=True)
        ovfenv = OvfEnv(ovfxml)
        ovfxml = re.sub("<UserPassword>.*?<", "<UserPassword>*<", ovfxml)
        ovfFilePath = os.path.join(CurrOS.GetLibDir(), OvfFileName)
        CurrOS.SetFileContents(ovfFilePath, self.xmlText)
        self.ovfenv = ovfenv

        CurrOS.UmountDvd()
        return ovfenv

    def reportProvisionStatus(self, status, subStatus, description, thumbprint):
        pass

    def reportAgentStatus(self, version, status, message):
        pass

    def reportExtensionStatus(self):
        pass

    def reportEvent(self):
        pass


