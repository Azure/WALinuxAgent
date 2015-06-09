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
from azurelinuxagent.utils.osutil import CurrOSUtil
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.fileutil as fileutil

VmmConfigFileName = "linuxosconfiguration.xml"
VmmStartupScriptName= "install"

class ScvmmHandler(object):
        
    def detectScvmmEnv(self):
        logger.Info("Detecting Microsoft System Center VMM Environment")
        CurrOSUtil.MountDvd(maxRetry=1, chk_err=False)
        mountPoint = CurrOSUtil.GetDvdMountPoint()
        found = os.path.isfile(os.path.join(mountPoint, VmmConfigFileName))
        if found: 
            self.startScvmmAgent()
        else:
            CurrOSUtil.UmountDvd(chk_err=False)
        return found

    def startScvmmAgent(self):
        logger.Info("Starting Microsoft System Center VMM Initialization "
                    "Process")
        mountPoint = CurrOSUtil.GetDvdMountPoint()
        startupScript = os.path.join(mountPoint, VmmStartupScriptName)
        subprocess.Popen(["/bin/bash", startupScript, "-p " + mountPoint])

