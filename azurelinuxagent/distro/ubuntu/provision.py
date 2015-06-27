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
import time
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
import azurelinuxagent.protocol as prot
from azurelinuxagent.exception import *
from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.distro.default.provision import ProvisionHandler

"""
On ubuntu image, provision could be disabled.
"""
class UbuntuProvisionHandler(ProvisionHandler):
    def process(self):
        logger.Info("Run ubuntu provision handler") 
        #If provision is enabled, run default provision handler
        if conf.GetSwitch("Provisioning.Enabled", False):
            super(UbuntuProvisionHandler, self).process()
            return

        provisioned = os.path.join(OSUtil.GetLibDir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.Info("Waiting cloud-init to finish provisioning.")
        protocol = prot.Factory.getDefaultProtocol()
        try:
            thumbprint = self.waitForSshHostKey()
            fileutil.SetFileContents(provisioned, "")

            logger.Info("Finished provisioning")
            status = prot.ProvisionStatus(status="Ready")
            status.properties.certificateThumbprint = thumbprint
            protocol.reportProvisionStatus(status)

        except ProvisionError as e:
            logger.Error("Provision failed: {0}", e)
            protocol.reportProvisionStatus(status="NotReady", subStatus=str(e))

    def waitForSshHostKey(self, maxRetry=60):
        keyPairType = conf.Get("Provisioning.SshHostKeyPairType", "rsa")
        path = '/etc/ssh/ssh_host_{0}_key'.format(keyPairType)
        for retry in range(0, maxRetry):
            if os.path.isfile(path):
                return self.getSshHostKeyThumbprint(keyPairType)
            if retry < maxRetry - 1:
                logger.Info("Wait for ssh host key be generated: {0}", path)
                time.sleep(5)
        raise ProvisionError("Ssh hsot key is not generated.")
