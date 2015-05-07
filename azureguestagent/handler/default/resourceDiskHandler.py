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

DataLossWarningFile="DATALOSS_WARNING_README.txt"
DataLossWarning="""\
WARNING: THIS IS A TEMPORARY DISK. 

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at : http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""

class ResourceDiskHandler(object):

    def startActivateResourceDisk(self, config):
        #TODO FreeBSD use Popen to open another process to do this
        diskThread = threading.Thread(target = self.activateResourceDisk,
                                      args = (config))
        diskThread.start()

    def activateResourceDisk(self, config):
        mountpoint = config.get("ResourceDisk.MountPoint", "/mnt/resource")
        fs = config.get("ResourceDisk.Filesystem", "ext3")
        mountpoint = CurrOSUtil.MountResourceDisk(mountpoint, fs)
        warningFile = os.path.join(mountpoint, DataLossWarningFile)
        fileutil.SetFileContents(warningFile, DataLossWarning)
        if config.getSwitch("ResourceDisk.EnabledSwap", False):
            sizeMB = config.getInt("ResourceDisk.SwapSizeMB", 0)
            CurrOSUtil.CreateSwapSpace(mountpoint, sizeMB)

