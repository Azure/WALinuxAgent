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
from CurrOS import LibDir, OvfMountPoint

CustomDataFile="CustomData"

class ProvisionHandler(object):
    def __init__(self, config, protocol, libDir=LibDir):
        self.config = config
        self.protocol = protocol
        self.libDir = libDir

    def provision(self):
        if self.config.getSwitch("Provisioning.Enabled"):
            return
        
        logger.Info("Provisioning image started")
        ovfenv = self.protocol.copyOvf()
    
        self.setHostName(ovfenv.getComputerName())
        self.createUserAccount(ovfenv.getUserName(), ovfenv.getUserPassword())
        self.deploySshPublicKeys(ovfenv.getSshPublicKeys)
        self.saveCustomData(ovfenv.getCustomData())

        if config.getSwitch("Provisioning.RegenerateSshHostKeyPair"):
            keyPairType = config.get("Provisioning.SshHostKeyPairType", "rsa")
            CurrOS.RegenerateSshHostkey(keyPairType)

        CurrOS.RestartSshService()
        self.reportSshHostkeyThumbnail()

        if config.getSwitch("Provisioning.DeleteRootPassword"):
            self.deleteRootPassword()

    def saveCustomData(self, customData):
        CurrOS.SetFileContents(os.path.join(self.libDir, CustomDataFile), 
                               customData)

    def deploySshPublicKeys(self, keys):
        pass
    
    def setHostName(self, hostName):
        pass

    def createUserAccount(self, userName, password):
        if userName is None:
            raise Exception("User name is empty.")
        if CurrOS.IsSysUser(userName):
            raise Exception("User:{0} is a system user.".format(userName))
        CurrOS.CreateUserAccount(userName, password)

    def reportSshHostkeyThumbnail(self):
        pass

    def deleteRootPassword(self):
        CurrOS.DeleteRootPassword()

