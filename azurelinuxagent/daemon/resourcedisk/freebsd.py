# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2020-2021 The FreeBSD Foundation
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
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

# Keeping 1GB sapce if configured swap size is larger than the disk size
MINIMAL_RESOURCE_PARTITION_SIZE = 1024 ** 3

class FreeBSDResourceDiskHandler(ResourceDiskHandler):
    """
    This class handles resource disk mounting for FreeBSD.

    The resource disk locates at following slot:
    scbus2 on blkvsc1 bus 0:
    <Msft Virtual Disk 1.0>            at scbus2 target 1 lun 0 (da1,pass2)
    """

    def __init__(self):  # pylint: disable=W0235
        super(FreeBSDResourceDiskHandler, self).__init__()

    @staticmethod
    def parse_gpart_show(data):
        dic = {}
        for line in data.split('\n'):
            if line:
                l = line.split()
                dic[l[3]] = l[4]
        return dic

    @staticmethod
    def parse_mount_list(data):
        dic = {}
        for line in data.split('\n'):
            if line:
                l = line.split()
                dic[l[2]] = l[0]
        return dic

    @staticmethod
    def get_next_partition(x):
        return x[:-1] + str(int(x[-1]) + 1)

    def mount_resource_disk(self, mount_point):
        fs = self.fs
        if fs != 'ufs':
            raise ResourceDiskError("Unsupported filesystem type: "
                                    "{0}, only ufs is supported.".format(fs))

        # 1. Detect device
        err, output = shellutil.run_get_output("gpart show | grep '=>'")
        if err:
            raise ResourceDiskError(
                "Unable to detect resource disk device:{0}".format(output))
        disks = self.parse_gpart_show(output)

        device = self.osutil.device_for_ide_port(1)
        if device is None or device not in disks:
            # fallback logic to find device
            err, output = shellutil.run_get_output(
                'camcontrol periphlist 2:1:0')
            if err:
                # try again on "3:1:0"
                err, output = shellutil.run_get_output(
                    'camcontrol periphlist 3:1:0')
                if err:
                    raise ResourceDiskError(
                        "Unable to detect resource disk device:{0}".format(output))

            # 'da1:  generation: 4 index: 1 status: MORE\npass2:  generation: 4 index: 2 status: LAST\n'
            for line in output.split('\n'):
                index = line.find(':')
                if index > 0:
                    geom_name = line[:index]
                    if geom_name in disks:
                        device = geom_name
                        break

        if not device:
            raise ResourceDiskError("Unable to detect resource disk device.")
        logger.info('Resource disk device {0} found.', device)

        # 2. Detect/create partition

        # count the target size of each partition
        err, output = shellutil.run_get_output("diskinfo {0}".format(device))
        if err:
            raise ResourceDiskError("Cannot get resource disk size.")
        disk_info = output.split()
        block_size = int(disk_info[1])

        err, output = shellutil.run_get_output("gpart show {0} | grep '=>'".format(device))
        if err:
            raise ResourceDiskError("Cannot get resource disk partition information.")
        disk_info = output.split()
        partition_size = int(disk_info[2]) * block_size

        swap_size = 0
        if conf.get_resourcedisk_enable_swap():
            swap_size_mb = conf.get_resourcedisk_swap_size_mb()
            swap_size = swap_size_mb * 1024 * 1024
        resource_size = partition_size - swap_size
        if resource_size < MINIMAL_RESOURCE_PARTITION_SIZE:
            resource_size = MINIMAL_RESOURCE_PARTITION_SIZE
            swap_size = partition_size - resource_size

        # get size of the current swap partition
        current_swap_size = 0
        err, output = shellutil.run_get_output(
            "gpart show {0} 2>/dev/null | grep freebsd-swap".format(device),
            chk_err=False)
        if output:
            current_swap_size = int(output.split()[1]) * block_size

        partition_table_type = disks.get(device)

        resource_provider_name = device + 'p1'

        # re-partition if needed
        if partition_table_type != 'GPT' or current_swap_size != swap_size:
            # unmount and swapoff if needed
            mount_list = shellutil.run_get_output("mount")[1]
            existing = self.osutil.get_mount_point(mount_list,
                                                   resource_provider_name)
            if existing:
                err, output = shellutil.run_get_output(
                    "umount {0}".format(mount_point), chk_err=False)

            swap_info = shellutil.run_get_output("swapctl -l")[1].split('\n')
            swap_device = None
            if len(swap_info) > 2:
                swap_device = swap_info[1].split()[0]
            if swap_device:
                err, output = shellutil.run_get_output(
                    "swapoff {0}".format(swap_device), chk_err=False)
                if swap_device.endswith('.eli'):
                    err, output = shellutil.run_get_output(
                        "geli detach {0}".format(swap_device), chk_err=False)

            if partition_table_type is not None:
                gaprt_destroy_cmd = "gpart destroy -F {0}".format(device)
                err, output = shellutil.run_get_output(gaprt_destroy_cmd,
                                                       chk_err=False)
                if err:
                    raise ResourceDiskError("Failed to destroy the "
                                            "partitioning scheme on {0}, "
                                            "error: {1}".format(device, output))
            gaprt_create_cmd = "gpart create -s GPT {0}".format(device)
            err, output = shellutil.run_get_output(gaprt_create_cmd,
                                                   chk_err=False)
            if err:
                raise ResourceDiskError("Failed to create new GPT on {0}, "
                                        "error: {1}".format(device, output))

        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_point(mount_list,
                                               resource_provider_name)
        if existing:
            logger.info("Resource disk {0} is already mounted".format(
                resource_provider_name))
            return existing

        # create resource partition
        if not os.path.exists("/dev/{0}".format(resource_provider_name)):
            if swap_size > 0:
                err, output = shellutil.run_get_output(
                    'gpart add -t freebsd-ufs -s {0}b {1}'.format(resource_size,
                                                                  device))
            else:
                err, output = shellutil.run_get_output(
                    'gpart add -t freebsd-ufs {0}'.format(device))
            if err:
                raise ResourceDiskError(
                    "Failed to add new freebsd-ufs partition to {0}, "
                    "error: {1}" .format(device, output))

            # create swap partition, just use all the space left
            if swap_size > 0:
                err, output = shellutil.run_get_output(
                    'gpart add -t freebsd-swap {0}'.format(device))
                if err:
                    raise ResourceDiskError(
                        "Failed to add new freebsd-swap partition to {0}, "
                        "error: {1}" .format(device, output))

        # 3. Mount partition
        fileutil.mkdir(mount_point, mode=0o755)

        need_newfs = True
        if current_swap_size == swap_size:
            # swap size is not adjusted,
            # i.e., the resource partition is not changed
            # check if a fs already exists
            fstyp_cmd = 'fstyp /dev/{0}'.format(resource_provider_name)
            err, output = shellutil.run_get_output(fstyp_cmd, chk_err=False)
            if not err and output == fs:
                need_newfs = False
                logger.info(
                    "Resource disk partition {0} is found at {1} "
                    "with fstype {2}".format(
                        resource_provider_name, mount_point, fs))
        elif swap_size < current_swap_size:
            # resource partition size is increased, try to growfs first
            err, output = shellutil.run_get_output(
                'growfs -y {0}'.format(resource_provider_name), chk_err=False)
            if not err:
                need_newfs = False
                logger.info(
                    "Resource disk partition {0} is found and enlarged at {1} "
                    "with fstype {2}".format(
                        resource_provider_name, mount_point, fs))
        # else
            # resource partition is shrunk and newfs is needed

        if need_newfs:
            logger.info('Creating {0} filesystem on partition {1}'.format(
                    fs, resource_provider_name))
            err, output = shellutil.run_get_output(
                'newfs -U {0}'.format(resource_provider_name))
            if err:
                raise ResourceDiskError(
                    "Failed to create new filesystem on partition {0}, "
                    "error: {1}" .format(resource_provider_name, output))

        mount_cmd = 'mount -t {0} /dev/{1} {2}'.format(
            fs, resource_provider_name, mount_point)
        err, output = shellutil.run_get_output(mount_cmd, chk_err=False)
        if err:
            raise ResourceDiskError(
                "Failed to mount partition {0}, error {1}".format(
                    resource_provider_name, output))

        logger.info(
            "Resource disk partition {0} is mounted at {1} "
            "with fstype {2}".format(
                resource_provider_name, mount_point, fs))
        return mount_point

    def create_swap_space(self, mount_point, size_mb):
        # done in mount_resource_disk()
        pass

    def enable_swap(self, mount_point):
        if conf.get_resourcedisk_swap_size_mb() <=0:
            return

        # get swap partition (geom provider)
        err, output = shellutil.run_get_output('mount')
        if err:
            raise ResourceDiskError("Unable to get mount information.")
        devices = self.parse_mount_list(output)
        resource_provider_name = devices[mount_point]
        swap_provider_name = self.get_next_partition(resource_provider_name)

        if conf.get_resourcedisk_enable_swap_encryption():
            shellutil.run("kldload -n aesni")
            shellutil.run("kldload -n cryptodev")
            shellutil.run("kldload -n geom_eli")
            shellutil.run("geli onetime -e AES-XTS -l 256"
                          " -d {0}".format(swap_provider_name))
            swap_provider_name += ".eli"
            shellutil.run("chmod 0600 {0}".format(swap_provider_name))

        err, output = shellutil.run_get_output(
			"swapctl -l | grep {0}".format(swap_provider_name))
        if not output:
            if shellutil.run("swapon {0}".format(swap_provider_name)):
                raise ResourceDiskError(swap_provider_name)

        size_mb = shellutil.run_get_output(
            "swapctl -lm | grep {0}".format(swap_provider_name))[1].split()[1]
        logger.info(
            "Enabled {0}MB of swap at {1}".format(size_mb, swap_provider_name))
