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
import walinuxagent.logger as logger
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.utils.shellutil as shellutil

CustomDataFile="CustomData"

class ProvisionHandler(object):
    def __init__(self, config, protocol):
        self.config = config
        self.protocol = protocol

    def provision(self):
        if self.config.getSwitch("Provisioning.Enabled"):
            return
        
        logger.Info("Provisioning image started")
        self.ovfenv = self.protocol.copyOvf()
   
        password = self.ovfenv.getUserPassword()
        self.ovfenv.clearUserPassword()

        self.setHostName()
        self.createUserAccount(self.ovfenv.getUserName(), password)
        self.deploySshPublicKeys()
        self.deploySshKeyPairs()
        self.saveCustomData()

        if config.getSwitch("Provisioning.RegenerateSshHostKeyPair"):
            keyPairType = config.get("Provisioning.SshHostKeyPairType", "rsa")
            CurrOS.RegenerateSshHostkey(keyPairType)

        #TODO Wait for host name published
        CurrOS.RestartSshService()
        
        #TODO report provision status
        self.protocol.reportProvisionStatus("")

        if config.getSwitch("Provisioning.DeleteRootPassword"):
            self.deleteRootPassword()

    def saveCustomData(self, customData):
        libDir = CurrOS.GetLibDir()
        CurrOS.SetFileContents(os.path.join(libDir, CustomDataFile), 
                               customData)

    def deploySshPublicKeys(self):
        for thumbprint, path in self.ovfenv.getSshPublicKeys():
            CurrOS.DeploySshPublicKey(self.ovfenv.getUserName(), thumbprint, path)
    
    def deploySshKeyPairs(self):
        for thumbprint, path in self.ovfenv.getSshKeyPairs():
            CurrOS.DeploySshKeyPair(self.ovfenv.getUserName(), thumbprint, path)

    def setHostName(self):
        pass

    def createUserAccount(self, userName, password):
        if userName is None:
            raise Exception("User name is empty.")
        if CurrOS.IsSysUser(userName):
            raise Exception("User:{0} is a system user.".format(userName))
        CurrOS.UpdateUserAccount(userName, password)

    def deleteRootPassword(self):
        CurrOS.DeleteRootPassword()

