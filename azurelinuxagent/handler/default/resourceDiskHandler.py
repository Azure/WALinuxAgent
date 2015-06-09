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
import re
import threading
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
from azurelinuxagent.event import AddExtensionEvent, WALAEventOperation
from azurelinuxagent.utils.osutil import CurrOSUtil
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
from azurelinuxagent.exception import ResourceDiskError

DataLossWarningFile="DATALOSS_WARNING_README.txt"
DataLossWarning="""\
WARNING: THIS IS A TEMPORARY DISK. 

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at : http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""

class ResourceDiskHandler(object):

    def startActivateResourceDisk(self):
        diskThread = threading.Thread(target = self.run)
        diskThread.start()
    
    def run(self):
        mountpoint = None
        if conf.GetSwitch("ResourceDisk.Format", False):
            mountpoint = self.activateResourceDisk()
        if mountpoint is not None and \
                conf.GetSwitch("ResourceDisk.EnableSwap", False):
            self.enableSwap(mountpoint)

    def activateResourceDisk(self):
        logger.Info("Activate resource disk")
        try:
            mountpoint = conf.Get("ResourceDisk.MountPoint", "/mnt/resource")
            fs = conf.Get("ResourceDisk.Filesystem", "ext3")
            mountpoint = self.mountResourceDisk(mountpoint, fs)
            warningFile = os.path.join(mountpoint, DataLossWarningFile)
            try:
                fileutil.SetFileContents(warningFile, DataLossWarning)
            except IOError as e:
                logger.Warn("Failed to write data loss warnning:{0}", e)
            return mountpoint
        except ResourceDiskError as e:
            logger.Error("Failed to mount resource disk {0}", e)
            AddExtensionEvent(name="WALA", isSuccess=False, message=str(e),
                              op=WALAEventOperation.ActivateResourceDisk)
    
    def enableSwap(self, mountpoint):
        logger.Info("Enable swap")
        try:
            sizeMB = conf.GetInt("ResourceDisk.SwapSizeMB", 0)
            self.createSwapSpace(mountpoint, sizeMB)
        except ResourceDiskError as e:
            logger.Error("Failed to enable swap {0}", e)

    def mountResourceDisk(self, mountpoint, fs):
        device = CurrOSUtil.DeviceForIdePort(1)
        if device is None:
            raise ResourceDiskError("unable to detect disk topology")

        device = "/dev/" + device
        mountlist = shellutil.RunGetOutput("mount")[1]
        existing = CurrOSUtil.GetMountPoint(mountlist, device)

        if(existing):
            logger.Info("Resource disk {0}1 is already mounted", device)
            return existing

        fileutil.CreateDir(mountpoint, mode=0755)  
    
        logger.Info("Detect GPT...")
        partition = device + "1"
        ret = shellutil.RunGetOutput("parted {0} print".format(device))
        if ret[0]:
            raise ResourceDiskError("({0}) {1}".format(device, ret[1]))
        
        if "gpt" in ret[1]:
            logger.Info("GPT detected")
            logger.Info("Get GPT partitions")
            parts = filter(lambda x : re.match("^\s*[0-9]+", x), 
                           ret[1].split("\n"))
            logger.Info("Found more than {0} GPT partitions.", len(parts))
            if len(parts) > 1:
                logger.Info("Remove old GPT partitions")
                for i in range(1, len(parts) + 1):
                    logger.Info("Remove partition: {0}", i)
                    shellutil.Run("parted {0} rm {1}".format(device, i))

                logger.Info("Create a new GPT partition using entire disk space")
                shellutil.Run("parted {0} mkpart primary 0% 100%".format(device))
                
                logger.Info("Format partition: {0} with fstype {1}",partition,fs)
                shellutil.Run("mkfs." + fs + " " + partition + " -F")
        else:
            logger.Info("GPT not detected")
            logger.Info("Check fstype")
            ret = shellutil.RunGetOutput("sfdisk -q -c {0} 1".format(device))
            if ret[1].rstrip() == "7" and fs != "ntfs":
                logger.Info("The partition is formatted with ntfs")
                logger.Info("Format partition: {0} with fstype {1}",partition,fs)
                shellutil.Run("sfdisk -c {0} 1 83".format(device))
                shellutil.Run("mkfs." + fs + " " + partition + " -F")

        logger.Info("Mount resource disk")
        retCode = shellutil.Run("mount {0} {1}".format(partition, mountpoint), 
                                chk_err=False)
        if retCode:
            logger.Warn("Failed to mount resource disk. Retry mounting")
            shellutil.Run("mkfs." + fs + " " + partition + " -F")
            retCode = shellutil.Run("mount {0} {1}".format(partition, mountpoint))
            if retCode:
                raise ResourceDiskError("({0}) {1}".format(partition, retCode))

        logger.Info("Resource disk ({0}) is mounted at {1} with fstype {2}",
                    device, mountpoint, fs)
        return mountpoint

    def createSwapSpace(self, mountpoint, sizeMB):
        sizeKB = sizeMB * 1024
        size = sizeKB * 1024
        swapfile = os.path.join(mountpoint, 'swapfile')
        swapList = shellutil.RunGetOutput("swapon -s")[1]

        if swapfile in swapList and os.path.getsize(swapfile) == size:
            logger.Info("Swap already enabled") 
            return 

        if os.path.isfile(swapfile) and os.path.getsize(swapfile) != size:
            logger.Info("Remove old swap file")
            shellutil.Run("swapoff -a", chk_err=False)
            os.remove(swapfile)

        if not os.path.isfile(swapfile):
            logger.Info("Create swap file")
            shellutil.Run(("dd if=/dev/zero of={0} bs=1024 "
                           "count={1}").format(swapfile, sizeKB))
            shellutil.Run("mkswap {0}".format(swapfile))
        if shellutil.Run("swapon {0}".format(swapfile)):
            raise ResourceDiskError("{0}".format(swapfile))
        logger.Info("Enabled {0}KB of swap at {1}".format(sizeKB, swapfile))

