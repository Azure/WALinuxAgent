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
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
from azurelinuxagent.event import AddExtensionEvent, WALAEventOperation
from azurelinuxagent.exception import *
from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.protocol as prot
import azurelinuxagent.protocol.ovfenv as ovf
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil

CustomDataFile="CustomData"

class ProvisionHandler(object):

    def process(self):
        #If provision is not enabled, return
        if not conf.GetSwitch("Provisioning.Enabled", True):
            logger.Info("Provisioning is disabled. Skip.")
            return

        provisioned = os.path.join(OSUtil.GetLibDir(), "provisioned")
        if os.path.isfile(provisioned):
            return
        
        logger.Info("Start provisioning.")
        protocol = prot.Factory.getDefaultProtocol()
        try:
            protocol.reportProvisionStatus("NotReady", "Provisioning", 
                                           "Starting")
            self.provision()
            fileutil.SetFileContents(provisioned, "")
            thumbprint = self.regenerateSshHostKey()
            protocol.reportProvisionStatus(status="Ready",
                                           thumbprint = thumbprint)
            AddExtensionEvent(name="WALA", isSuccess=True, message="",
                              op=WALAEventOperation.Provision)
        except ProvisionError as e:
            logger.Error("Provision failed: {0}", e)
            protocol.reportProvisionStatus(status="NotReady", subStatus=str(e))
            AddExtensionEvent(name="WALA", isSuccess=False, message=str(e),
                              op=WALAEventOperation.Provision)

    
    def regenerateSshHostKey(self):
        keyPairType = conf.Get("Provisioning.SshHostKeyPairType", "rsa")
        if conf.GetSwitch("Provisioning.RegenerateSshHostKeyPair"):
            shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
            shellutil.Run(("ssh-keygen -N '' -t {0} -f /etc/ssh/ssh_host_{1}_key"
                           "").format(keyPairType, keyPairType))
        thumbprint = self.getSshHostKeyThumbprint(keyPairType)
        return thumbprint

    def getSshHostKeyThumbprint(self, keyPairType):
        cmd = "ssh-keygen -lf /etc/ssh/ssh_host_{0}_key.pub".format(keyPairType)
        ret = shellutil.RunGetOutput(cmd)
        if ret[0] == 0:
            return ret[1].rstrip().split()[1].replace(':', '')
        else:
            raise ProvisionError(("Failed to generate ssh host key: "
                                  "ret={0}, out= {1}").format(ret[0], ret[1]))
            

    def provision(self):
        try:
            ovfenv = ovf.CopyOvfEnv()
        except prot.ProtocolError as e:
            raise ProvisionError("Failed to copy ovf-env.xml: {0}".format(e))

        password = ovfenv.getUserPassword()
        ovfenv.clearUserPassword()

        OSUtil.SetHostname(ovfenv.getComputerName())
        OSUtil.PublishHostname(ovfenv.getComputerName())
        OSUtil.UpdateUserAccount(ovfenv.getUserName(), password)

        if password is not None:
            userSalt = conf.GetSwitch("Provision.UseSalt", True)
            saltType = conf.GetSwitch("Provision.SaltType", 6)
            OSUtil.ChangePassword(ovfenv.getUserName(), password, userSalt,
                                      saltType)

        OSUtil.ConfigSshd(ovfenv.getDisableSshPasswordAuthentication())

        #Disable selinux temporary
        sel = OSUtil.IsSelinuxRunning()
        if sel:
            OSUtil.SetSelinuxEnforce(0)

        self.deploySshPublicKeys(ovfenv)
        self.deploySshKeyPairs(ovfenv)
        self.saveCustomData(ovfenv)

        if sel:
            OSUtil.SetSelinuxEnforce(1)

        OSUtil.RestartSshService()

        if conf.GetSwitch("Provisioning.DeleteRootPassword"):
            OSUtil.DeleteRootPassword()


    def saveCustomData(self, ovfenv):
        customData = ovfenv.getCustomData()
        if customData is None:
            return
        #TODO  port Abel's fix to decoding custom data
        libDir = OSUtil.GetLibDir()
        fileutil.SetFileContents(os.path.join(libDir, CustomDataFile), 
                                 OSUtil.TranslateCustomData(customData))

    def deploySshPublicKeys(self, ovfenv):
        for thumbprint, path in ovfenv.getSshPublicKeys():
            OSUtil.DeploySshPublicKey(ovfenv.getUserName(), thumbprint, path)
    
    def deploySshKeyPairs(self, ovfenv):
        for thumbprint, path in ovfenv.getSshKeyPairs():
            OSUtil.DeploySshKeyPair(ovfenv.getUserName(), thumbprint, path)
   
