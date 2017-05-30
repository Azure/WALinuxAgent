# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
# Copyright 2017 Reyk Floeter <reyk@openbsd.org>
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
# Requires Python 2.4+ and OpenSSL 1.0+
#
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class OpenBSDResourceDiskHandler(ResourceDiskHandler):
    def __init__(self):
        super(OpenBSDResourceDiskHandler, self).__init__()
        # Fase File System (FFS) is UFS
        if self.fs == 'ufs' or self.fs == 'ufs2':
            self.fs = 'ffs'

    def create_swap_space(self, mount_point, size_mb):
        pass

    def enable_swap(self, mount_point):
        size_mb = conf.get_resourcedisk_swap_size_mb()
        if size_mb:
            logger.info("Enable swap")
            device = self.osutil.device_for_ide_port(1)
            err, output = shellutil.run_get_output("swapctl -a /dev/"
                                                   "{0}b".format(device),
                                                   chk_err=False)
            if err:
                logger.error("Failed to enable swap, error {0}", output)

    def mount_resource_disk(self, mount_point):
        fs = self.fs
        if fs != 'ffs':
            raise ResourceDiskError("Unsupported filesystem type: {0}, only "
                                    "ufs/ffs is supported.".format(fs))

        # 1. Get device
        device = self.osutil.device_for_ide_port(1)

        if not device:
            raise ResourceDiskError("Unable to detect resource disk device.")
        logger.info('Resource disk device {0} found.', device)

        # 2. Get partition
        partition = "/dev/{0}a".format(device)

        # 3. Mount partition
        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_point(mount_list, partition)

        if existing:
            logger.info("Resource disk {0} is already mounted", partition)
            return existing

        fileutil.mkdir(mount_point, mode=0o755)
        mount_cmd = 'mount -t {0} {1} {2}'.format(self.fs,
                                                  partition, mount_point)
        err = shellutil.run(mount_cmd, chk_err=False)
        if err:
            logger.info('Creating {0} filesystem on {1}'.format(fs, device))

            fdisk_cmd = "/sbin/fdisk -yi {0}".format(device)
            err, output = shellutil.run_get_output(fdisk_cmd, chk_err=False)
            if err:
                raise ResourceDiskError("Failed to create new MBR on {0}, "
                                        "error: {1}".format(device, output))

            size_mb = conf.get_resourcedisk_swap_size_mb()
            if size_mb:
                if size_mb > 512 * 1024:
                    size_mb = 512 * 1024
                disklabel_cmd = ("echo -e '{0} 1G-* 50%\nswap 1-{1}M 50%' "
                                 "| disklabel -w -A -T /dev/stdin "
                                 "{2}").format(mount_point, size_mb, device)
                ret, output = shellutil.run_get_output(
                    disklabel_cmd, chk_err=False)
                if ret:
                    raise ResourceDiskError("Failed to create new disklabel "
                                            "on {0}, error "
                                            "{1}".format(device, output))

            err, output = shellutil.run_get_output("newfs -O2 {0}a"
                                                   "".format(device))
            if err:
                raise ResourceDiskError("Failed to create new filesystem on "
                                        "partition {0}, error "
                                        "{1}".format(partition, output))

            err, output = shellutil.run_get_output(mount_cmd, chk_err=False)
            if err:
                raise ResourceDiskError("Failed to mount partition {0}, "
                                        "error {1}".format(partition, output))

        logger.info("Resource disk partition {0} is mounted at {1} with fstype "
                    "{2}", partition, mount_point, fs)
        return mount_point
