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
from azureguestagent.utils.osutil import CurrOSUtil
import azureguestagent.utils.fileutil as fileutil

VmmConfigFileName = "linuxosconfiguration.xml"
VmmStartupScriptName= "install"

class ScvmmHandler(object):
        
    def detectScvmmEnv(self):
        CurrOSUtil.MountDvd(maxRetry=0, chk_err=False)
        mountPoint = CurrOSUtil.GetDvdMountPoint()
        return os.path.isfile(os.path.join(mountPoint, VmmConfigFileName))

    def startScvmmAgent(self):
        logger.Info("Starting Microsoft System Center VMM Initialization "
                    "Process")
        mountPoint = CurrOSUtil.GetDvdMountPoint()
        startupScript = os.path.join(mountPoint, VmmStartupScriptName)
        subprocess.Popen(["/bin/bash", startupScript, "-p " + mountPoint])

