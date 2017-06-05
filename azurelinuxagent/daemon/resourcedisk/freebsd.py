# Microsoft Azure Linux Agent
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
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class FreeBSDResourceDiskHandler(ResourceDiskHandler):
    """
    This class handles resource disk mounting for FreeBSD.

    The resource disk locates at following slot:
    scbus2 on blkvsc1 bus 0:
    <Msft Virtual Disk 1.0>            at scbus2 target 1 lun 0 (da1,pass2)

    There are 2 variations based on partition table type:
    1. MBR: The resource disk partition is /dev/da1s1
    2. GPT: The resource disk partition is /dev/da1p2, /dev/da1p1 is for reserved usage.
    """
    def __init__(self):
        super(FreeBSDResourceDiskHandler, self).__init__()

    @staticmethod
    def parse_gpart_list(data):
        dic = {}
        for line in data.split('\n'):
            if line.find("Geom name: ") != -1:
                geom_name = line[11:]
            elif line.find("scheme: ") != -1:
                dic[geom_name] = line[8:]
        return dic

    def mount_resource_disk(self, mount_point):
        fs = self.fs
        if fs != 'ufs':
            raise ResourceDiskError("Unsupported filesystem type:{0}, only ufs is supported.".format(fs))

        # 1. Detect device
        err, output = shellutil.run_get_output('gpart list')
        if err:
            raise ResourceDiskError("Unable to detect resource disk device:{0}".format(output))
        disks = self.parse_gpart_list(output)

        device = self.osutil.device_for_ide_port(1)
        if device is None or not device in disks:
        # fallback logic to find device
            err, output = shellutil.run_get_output('camcontrol periphlist 2:1:0')
            if err:
                # try again on "3:1:0"
                err, output = shellutil.run_get_output('camcontrol periphlist 3:1:0')
                if err:
                    raise ResourceDiskError("Unable to detect resource disk device:{0}".format(output))

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

        # 2. Detect partition
        partition_table_type = disks[device]

        if partition_table_type == 'MBR':
            provider_name = device + 's1'
        elif partition_table_type == 'GPT':
            provider_name = device + 'p2'
        else:
            raise ResourceDiskError("Unsupported partition table type:{0}".format(output))

        err, output = shellutil.run_get_output('gpart show -p {0}'.format(device))
        if err or output.find(provider_name) == -1:
            raise ResourceDiskError("Resource disk partition not found.")

        partition = '/dev/' + provider_name
        logger.info('Resource disk partition {0} found.', partition)

        # 3. Mount partition
        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_point(mount_list, partition)

        if existing:
            logger.info("Resource disk {0} is already mounted", partition)
            return existing

        fileutil.mkdir(mount_point, mode=0o755)
        mount_cmd = 'mount -t {0} {1} {2}'.format(fs, partition, mount_point)
        err = shellutil.run(mount_cmd, chk_err=False)
        if err:
            logger.info('Creating {0} filesystem on partition {1}'.format(fs, partition))
            err, output = shellutil.run_get_output('newfs -U {0}'.format(partition))
            if err:
                raise ResourceDiskError("Failed to create new filesystem on partition {0}, error:{1}"
                                        .format(partition, output))
            err, output = shellutil.run_get_output(mount_cmd, chk_err=False)
            if err:
                raise ResourceDiskError("Failed to mount partition {0}, error {1}".format(partition, output))

        logger.info("Resource disk partition {0} is mounted at {1} with fstype {2}", partition, mount_point, fs)
        return mount_point
