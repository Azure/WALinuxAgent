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
import walinuxagent.logger as logger
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.utils.shellutil as shellutil

CustomDataFile="CustomData"

class ProvisionHandler(object):
    def __init__(self, config, protocol, envMonitor):
        self.config = config
        self.protocol = protocol
        self.envMonitor = envMonitor

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
        self.reportProvisionStatus("NotReady", "Running", "Starting")

        self.ovfenv = self.protocol.copyOvf()
        password = self.ovfenv.getUserPassword()
        self.ovfenv.clearUserPassword()

        self.envMonitor.setHostname(self.ovfenv.getHostName())
        CurrOS.UpdateUserAccount(self.ovfenv.getUserName(), password)

        #Disable selinux temporary
        sel = CurrOS.isSelinuxRunning()
        if sel:
            CurrOS.SetSelinuxEnforce(0)
        self.deploySshPublicKeys()
        self.deploySshKeyPairs()
        self.saveCustomData()
        if sel:
            CurrOS.SetSelinuxEnforce(1)

        keyPairType = config.get("Provisioning.SshHostKeyPairType", "rsa")
        if config.getSwitch("Provisioning.RegenerateSshHostKeyPair"):
            CurrOS.RegenerateSshHostkey(keyPairType)

        self.envMonitor.waitForHostnamePublishing()
        CurrOS.RestartSshService()

        if config.getSwitch("Provisioning.DeleteRootPassword"):
            CurrOS.DeleteRootPassword()

    def saveCustomData(self, customData):
        libDir = CurrOS.GetLibDir()
        CurrOS.SetFileContents(os.path.join(libDir, CustomDataFile), 
                               CurrOS.TranslateCustomData(customData))

    def deploySshPublicKeys(self):
        for thumbprint, path in self.ovfenv.getSshPublicKeys():
            CurrOS.DeploySshPublicKey(self.ovfenv.getUserName(), thumbprint, path)
    
    def deploySshKeyPairs(self):
        for thumbprint, path in self.ovfenv.getSshKeyPairs():
            CurrOS.DeploySshKeyPair(self.ovfenv.getUserName(), thumbprint, path)
   
