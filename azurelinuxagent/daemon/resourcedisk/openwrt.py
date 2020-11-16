# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2018 Sonus Networks, Inc. (d.b.a. Ribbon Communications Operating Company)
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
# Requires Python 2.6+ and Openssl 1.0+
#
import os
from time import sleep

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class OpenWRTResourceDiskHandler(ResourceDiskHandler):
    def __init__(self):
        super(OpenWRTResourceDiskHandler, self).__init__()
        # Fase File System (FFS) is UFS
        if self.fs == 'ufs' or self.fs == 'ufs2':
            self.fs = 'ffs'

    def reread_partition_table(self, device):
        ret, output = shellutil.run_get_output("hdparm -z {0}".format(device), chk_err=False)  # pylint: disable=W0612
        if ret != 0:
            logger.warn("Failed refresh the partition table.")

    def mount_resource_disk(self, mount_point):
        device = self.osutil.device_for_ide_port(1)
        if device is None:
            raise ResourceDiskError("unable to detect disk topology")
        logger.info('Resource disk device {0} found.', device)

        # 2. Get partition
        device = "/dev/{0}".format(device)
        partition = device + "1"
        logger.info('Resource disk partition {0} found.', partition)

        # 3. Mount partition
        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_point(mount_list, device)
        if existing:
            logger.info("Resource disk [{0}] is already mounted [{1}]",
                        partition,
                        existing)
            return existing

        try:
            fileutil.mkdir(mount_point, mode=0o755)
        except OSError as ose:
            msg = "Failed to create mount point " \
                  "directory [{0}]: {1}".format(mount_point, ose)
            logger.error(msg)
            raise ResourceDiskError(msg=msg, inner=ose)

        force_option = 'F'
        if self.fs == 'xfs':
            force_option = 'f'
        mkfs_string = "mkfs.{0} -{2} {1}".format(self.fs, partition, force_option)

        # Compare to the Default mount_resource_disk, we don't check for GPT that is not supported on OpenWRT
        ret = self.change_partition_type(suppress_message=True, option_str="{0} 1 -n".format(device))
        ptype = ret[1].strip()
        if ptype == "7" and self.fs != "ntfs":
            logger.info("The partition is formatted with ntfs, updating "
                        "partition type to 83")
            self.change_partition_type(suppress_message=False, option_str="{0} 1 83".format(device))
            self.reread_partition_table(device)
            logger.info("Format partition [{0}]", mkfs_string)
            shellutil.run(mkfs_string)
        else:
            logger.info("The partition type is {0}", ptype)

        mount_options = conf.get_resourcedisk_mountoptions()
        mount_string = self.get_mount_string(mount_options,
                                             partition,
                                             mount_point)
        attempts = 5
        while not os.path.exists(partition) and attempts > 0:
            logger.info("Waiting for partition [{0}], {1} attempts remaining",
                        partition,
                        attempts)
            sleep(5)
            attempts -= 1

        if not os.path.exists(partition):
            raise ResourceDiskError("Partition was not created [{0}]".format(partition))

        if os.path.ismount(mount_point):
            logger.warn("Disk is already mounted on {0}", mount_point)
        else:
            # Some kernels seem to issue an async partition re-read after a
            # command invocation. This causes mount to fail if the
            # partition re-read is not complete by the time mount is
            # attempted. Seen in CentOS 7.2. Force a sequential re-read of
            # the partition and try mounting.
            logger.info("Mounting after re-reading partition info.")

            self.reread_partition_table(device)

            logger.info("Mount resource disk [{0}]", mount_string)
            ret, output = shellutil.run_get_output(mount_string)
            if ret:
                logger.warn("Failed to mount resource disk. "
                            "Attempting to format and retry mount. [{0}]",
                            output)

                shellutil.run(mkfs_string)
                ret, output = shellutil.run_get_output(mount_string)
                if ret:
                    raise ResourceDiskError("Could not mount {0} "
                                            "after syncing partition table: "
                                            "[{1}] {2}".format(partition,
                                                               ret,
                                                               output))

        logger.info("Resource disk {0} is mounted at {1} with {2}",
                    device,
                    mount_point,
                    self.fs)
        return mount_point
