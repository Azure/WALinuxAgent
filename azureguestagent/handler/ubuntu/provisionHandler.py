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
import azureguestagent.logger as logger
import azureguestagent.conf as conf
from azureguestagent.utils.osutil import CurrOSUtil
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.fileutil as fileutil

"""
On ubuntu image, provision could be disabled.
"""
class UbuntuProvisionHandler(ProvisionHandler):
    def process(self):
        
        #If provision is enabled, run default provision handler
        if conf.GetSwitch("Provisioning.Enabled", True):
            super(UbuntuProvisionHandler, self).process()
            return

        provisoned = os.path.join(CurrOSUtil.GetLibDir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.Info("Waiting cloud-init to finish provisioning.")
        protocol = prot.GetDefaultProtocol()
        try:
            thumbprint = self.waitForSshHostKey()
            protocol.reportProvisionStatus(status="Ready",
                                           thumbprint = thumbprint)
            fileutil.SetFileContents(provisoned, "")
        except Provisioning as e:
            logger.Error("Provision failed: {0}", e)
            protocol.reportProvisionStatus(status="NotReady", subStatus=str(e))

    def waitForSshHostKey(self, maxRetry=60):
        keyPairType = self.config.get("Provisioning.SshHostKeyPairType", "rsa")
        path = '/etc/ssh/ssh_host_{0}_key'.format(keyPairType)
        for retry in range(0, maxRetry):
            if os.path.isfile(path):
                return self.getSshHostKeyThumbprint(keyPairType)
            logger.Info("Wait for ssh host key be generated: {0}", path)
            time.sleep(5)
        raise ProvisionError("Ssh hsot key is not generated.")
