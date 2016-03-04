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
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import add_event, WALAEventOperation
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.common.osutil import get_osutil

DATALOSS_WARNING_FILE_NAME="DATALOSS_WARNING_README.txt"
DATA_LOSS_WARNING="""\
WARNING: THIS IS A TEMPORARY DISK.

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at : http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""

class ResourceDiskHandler(object):
    def __init__(self):
        self.osutil = get_osutil()

    def start_activate_resource_disk(self):
        disk_thread = threading.Thread(target = self.run)
        disk_thread.start()

    def run(self):
        mount_point = None
        if conf.get_resourcedisk_format():
            mount_point = self.activate_resource_disk()
        if mount_point is not None and \
                conf.get_resourcedisk_enable_swap():
            self.enable_swap(mount_point)

    def activate_resource_disk(self):
        logger.info("Activate resource disk")
        try:
            mount_point = conf.get_resourcedisk_mountpoint()
            fs = conf.get_resourcedisk_filesystem()
            mount_point = self.mount_resource_disk(mount_point, fs)
            warning_file = os.path.join(mount_point, DATALOSS_WARNING_FILE_NAME)
            try:
                fileutil.write_file(warning_file, DATA_LOSS_WARNING)
            except IOError as e:
                logger.warn("Failed to write data loss warnning:{0}", e)
            return mount_point
        except ResourceDiskError as e:
            logger.error("Failed to mount resource disk {0}", e)
            add_event(name="WALA", is_success=False, message=ustr(e),
                              op=WALAEventOperation.ActivateResourceDisk)

    def enable_swap(self, mount_point):
        logger.info("Enable swap")
        try:
            size_mb = conf.get_resourcedisk_swap_size_mb()
            self.create_swap_space(mount_point, size_mb)
        except ResourceDiskError as e:
            logger.error("Failed to enable swap {0}", e)

    def mount_resource_disk(self, mount_point, fs):
        device = self.osutil.device_for_ide_port(1)
        if device is None:
            raise ResourceDiskError("unable to detect disk topology")

        device = "/dev/" + device
        mountlist = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_point(mountlist, device)

        if(existing):
            logger.info("Resource disk {0}1 is already mounted", device)
            return existing

        fileutil.mkdir(mount_point, mode=0o755)

        logger.info("Detect GPT...")
        partition = device + "1"
        ret = shellutil.run_get_output("parted {0} print".format(device))
        if ret[0]:
            raise ResourceDiskError("({0}) {1}".format(device, ret[1]))

        if "gpt" in ret[1]:
            logger.info("GPT detected")
            logger.info("Get GPT partitions")
            parts = [x for x in ret[1].split("\n") if re.match("^\s*[0-9]+", x)]
            logger.info("Found more than {0} GPT partitions.", len(parts))
            if len(parts) > 1:
                logger.info("Remove old GPT partitions")
                for i in range(1, len(parts) + 1):
                    logger.info("Remove partition: {0}", i)
                    shellutil.run("parted {0} rm {1}".format(device, i))

                logger.info("Create a new GPT partition using entire disk space")
                shellutil.run("parted {0} mkpart primary 0% 100%".format(device))

                logger.info("Format partition: {0} with fstype {1}",partition,fs)
                shellutil.run("mkfs." + fs + " " + partition + " -F")
        else:
            logger.info("GPT not detected")
            logger.info("Check fstype")
            ret = shellutil.run_get_output("sfdisk -q -c {0} 1".format(device))
            if ret[1].rstrip() == "7" and fs != "ntfs":
                logger.info("The partition is formatted with ntfs")
                logger.info("Format partition: {0} with fstype {1}",partition,fs)
                shellutil.run("sfdisk -c {0} 1 83".format(device))
                shellutil.run("mkfs." + fs + " " + partition + " -F")

        logger.info("Mount resource disk")
        ret = shellutil.run("mount {0} {1}".format(partition, mount_point),
                                chk_err=False)
        if ret:
            logger.warn("Failed to mount resource disk. Retry mounting")
            shellutil.run("mkfs." + fs + " " + partition + " -F")
            ret = shellutil.run("mount {0} {1}".format(partition, mount_point))
            if ret:
                raise ResourceDiskError("({0}) {1}".format(partition, ret))

        logger.info("Resource disk ({0}) is mounted at {1} with fstype {2}",
                    device, mount_point, fs)
        return mount_point

    def create_swap_space(self, mount_point, size_mb):
        size_kb = size_mb * 1024
        size = size_kb * 1024
        swapfile = os.path.join(mount_point, 'swapfile')
        swaplist = shellutil.run_get_output("swapon -s")[1]

        if swapfile in swaplist and os.path.getsize(swapfile) == size:
            logger.info("Swap already enabled")
            return

        if os.path.isfile(swapfile) and os.path.getsize(swapfile) != size:
            logger.info("Remove old swap file")
            shellutil.run("swapoff -a", chk_err=False)
            os.remove(swapfile)

        if not os.path.isfile(swapfile):
            logger.info("Create swap file")
            shellutil.run(("dd if=/dev/zero of={0} bs=1024 "
                           "count={1}").format(swapfile, size_kb))
            shellutil.run("mkswap {0}".format(swapfile))
        if shellutil.run("swapon {0}".format(swapfile)):
            raise ResourceDiskError("{0}".format(swapfile))
        logger.info("Enabled {0}KB of swap at {1}".format(size_kb, swapfile))

