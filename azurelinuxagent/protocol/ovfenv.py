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

from azurelinuxagent.protocol.common import *

from azurelinuxagent.utils.osutil import OSUtil, OSUtilError

def GetOvfEnv():
    ovfFilePath = os.path.join(OSUtil.GetLibDir(), OvfFileName)
    if os.path.isfile(ovfFilePath):
        xmlText = fileutil.GetFileContents(ovfFilePath)        
        return OvfEnv(xmlText)
    else:
        raise ProtocolError("ovf-env.xml is missing.")

def CopyOvfEnv():
    """
    Copy ovf env file from dvd to hard disk. 
    Remove password before save it to the disk
    """
    try:
        OSUtil.MountDvd()
        ovfFile = OSUtil.GetOvfEnvPathOnDvd()

        ovfxml = fileutil.GetFileContents(ovfFile, removeBom=True)
        ovfenv = OvfEnv(ovfxml)
        ovfxml = re.sub("<UserPassword>.*?<", "<UserPassword>*<", ovfxml)
        ovfFilePath = os.path.join(OSUtil.GetLibDir(), OvfFileName)
        fileutil.SetFileContents(ovfFilePath, ovfxml)
        OSUtil.UmountDvd()
    except IOError as e:
        raise ProtocolError(str(e))
    except OSUtilError as e:
        raise ProtocolError(str(e))
    return ovfenv

OvfFileName="ovf-env.xml"
class OvfEnv(object):
    """
    Read, and process provisioning info from provisioning file OvfEnv.xml
    """
    def __init__(self, xmlText):
        if xmlText is None:
            raise ValueError("ovf-env is None")
        logger.Verbose("Load ovf-env.xml")
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
        dom = xml.dom.minidom.parseString(xmlText)
        if len(dom.getElementsByTagNameNS(self.OvfNs, "Environment")) != 1:
            logger.Error("Unable to parse OVF XML.")
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

