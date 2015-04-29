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
import traceback
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import CurrOS, CurrOSInfo
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil

CustomDataFile="CustomData"

class ProvisionHandler(object):
    def __init__(self, config, protocol):
        self.config = config
        self.protocol = protocol

    def provision(self):
        try:
            if self.config.getSwitch("Provisioning.Enabled"):
                self._provision()
            else:
                #In some distro like Ubuntu, cloud init does the provision
                #In this case, we need to wait the cloud init to complete 
                #provision work and generate ssh host key
                keyPairType = self.config.get("Provisioning.SshHostKeyPairType", "rsa")
                CurrOS.WaitForSshHostKey(keyPairType)

            keyPairType = self.config.get("Provisioning.SshHostKeyPairType", "rsa")
            thumbprint = CurrOS.GetSshHostKeyThumbprint(keyPairType)
            self.protocol.reportProvisionStatus(status="Ready",
                                                thumbprint = thumbprint)
        except Exception, e:
            logger.Error("Provision failed: {0} {1}", e, traceback.format_exc())
            self.protocol.reportProvisionStatus(status="NotReady",
                                                subStatus="Provisioning Failed")
            raise e

    def _provision(self):
        logger.Info("Provisioning image started")
        self.protocol.reportProvisionStatus("NotReady", "Provisioning", "Starting")

        self.ovfenv = self.copyOvf()
        password = self.ovfenv.getUserPassword()
        self.ovfenv.clearUserPassword()

        CurrOS.SetHostname(self.ovfenv.getComputerName())
        CurrOS.PublishHostname(self.ovfenv.getComputerName())
        CurrOS.UpdateUserAccount(self.ovfenv.getUserName(), password)

        CurrOS.ConfigSshd(self.ovfenv.getDisableSshPasswordAuthentication())
        #Disable selinux temporary
        sel = CurrOS.IsSelinuxRunning()
        if sel:
            CurrOS.SetSelinuxEnforce(0)
        self.deploySshPublicKeys()
        self.deploySshKeyPairs()
        self.saveCustomData()
        if sel:
            CurrOS.SetSelinuxEnforce(1)

        keyPairType = self.config.get("Provisioning.SshHostKeyPairType", "rsa")
        if self.config.getSwitch("Provisioning.RegenerateSshHostKeyPair"):
            CurrOS.RegenerateSshHostkey(keyPairType)

        CurrOS.RestartSshService()

        if self.config.getSwitch("Provisioning.DeleteRootPassword"):
            CurrOS.DeleteRootPassword()

    def copyOvf(self):
        """
        Copy ovf env file from dvd to hard disk. 
        Remove password before save it to the disk
        """
        ovfFile = CurrOS.GetOvfEnvPathOnDvd()
        CurrOS.MountDvd()

        if not os.path.isfile(ovfFile):
            raise Exception("Unable to provision: Missing ovf-env.xml on DVD")
        ovfxml = fileutil.GetFileContents(ovfFile, removeBom=True)
        ovfenv = OvfEnv(ovfxml)
        ovfxml = re.sub("<UserPassword>.*?<", "<UserPassword>*<", ovfxml)
        ovfFilePath = os.path.join(CurrOS.GetLibDir(), OvfFileName)
        fileutil.SetFileContents(ovfFilePath, ovfxml)

        CurrOS.UmountDvd()
        return ovfenv

    def saveCustomData(self):
        customData = self.ovfenv.getCustomData()
        if customData is None:
            return
        libDir = CurrOS.GetLibDir()
        fileutil.SetFileContents(os.path.join(libDir, CustomDataFile), 
                                 CurrOS.TranslateCustomData(customData))

    def deploySshPublicKeys(self):
        for thumbprint, path in self.ovfenv.getSshPublicKeys():
            CurrOS.DeploySshPublicKey(self.ovfenv.getUserName(), thumbprint, path)
    
    def deploySshKeyPairs(self):
        for thumbprint, path in self.ovfenv.getSshKeyPairs():
            CurrOS.DeploySshKeyPair(self.ovfenv.getUserName(), thumbprint, path)
   
