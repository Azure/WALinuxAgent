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
import sys
import threading
from time import sleep

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import add_event, WALAEventOperation
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME

DATALOSS_WARNING_FILE_NAME = "DATALOSS_WARNING_README.txt"
DATA_LOSS_WARNING = """\
WARNING: THIS IS A TEMPORARY DISK.

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at :
http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""


class ResourceDiskHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.fs = conf.get_resourcedisk_filesystem()

    def start_activate_resource_disk(self):
        disk_thread = threading.Thread(target=self.run)
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
            mount_point = self.mount_resource_disk(mount_point)
            warning_file = os.path.join(mount_point,
                                        DATALOSS_WARNING_FILE_NAME)
            try:
                fileutil.write_file(warning_file, DATA_LOSS_WARNING)
            except IOError as e:
                logger.warn("Failed to write data loss warning:{0}", e)
            return mount_point
        except ResourceDiskError as e:
            logger.error("Failed to mount resource disk {0}", e)
            add_event(name=AGENT_NAME, is_success=False, message=ustr(e),
                      op=WALAEventOperation.ActivateResourceDisk)

    def enable_swap(self, mount_point):
        logger.info("Enable swap")
        try:
            size_mb = conf.get_resourcedisk_swap_size_mb()
            self.create_swap_space(mount_point, size_mb)
        except ResourceDiskError as e:
            logger.error("Failed to enable swap {0}", e)

    def reread_partition_table(self, device):
        if shellutil.run("sfdisk -R {0}".format(device), chk_err=False):
            shellutil.run("blockdev --rereadpt {0}".format(device),
                          chk_err=False)

    def mount_resource_disk(self, mount_point):
        device = self.osutil.device_for_ide_port(1)
        if device is None:
            raise ResourceDiskError("unable to detect disk topology")

        device = "/dev/{0}".format(device)
        partition = device + "1"
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

        logger.info("Examining partition table")
        ret = shellutil.run_get_output("parted {0} print".format(device))
        if ret[0]:
            raise ResourceDiskError("Could not determine partition info for "
                                    "{0}: {1}".format(device, ret[1]))

        force_option = 'F'
        if self.fs == 'xfs':
            force_option = 'f'
        mkfs_string = "mkfs.{0} -{2} {1}".format(self.fs, partition, force_option)

        if "gpt" in ret[1]:
            logger.info("GPT detected, finding partitions")
            parts = [x for x in ret[1].split("\n") if
                     re.match("^\s*[0-9]+", x)]
            logger.info("Found {0} GPT partition(s).", len(parts))
            if len(parts) > 1:
                logger.info("Removing old GPT partitions")
                for i in range(1, len(parts) + 1):
                    logger.info("Remove partition {0}", i)
                    shellutil.run("parted {0} rm {1}".format(device, i))

                logger.info("Creating new GPT partition")
                shellutil.run("parted {0} mkpart primary 0% 100%".format(device))

                logger.info("Format partition [{0}]", mkfs_string)
                shellutil.run(mkfs_string)
        else:
            logger.info("GPT not detected, determining filesystem")
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

        logger.info("Mount resource disk [{0}]", mount_string)
        ret, output = shellutil.run_get_output(mount_string, chk_err=False)
        # if the exit code is 32, then the resource disk can be already mounted
        if ret == 32 and output.find("is already mounted") != -1:
            logger.warn("Could not mount resource disk: {0}", output)
        elif ret != 0:
            # Some kernels seem to issue an async partition re-read after a
            # 'parted' command invocation. This causes mount to fail if the
            # partition re-read is not complete by the time mount is
            # attempted. Seen in CentOS 7.2. Force a sequential re-read of
            # the partition and try mounting.
            logger.warn("Failed to mount resource disk. "
                        "Retry mounting after re-reading partition info.")

            self.reread_partition_table(device)

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

    def change_partition_type(self, suppress_message, option_str):
        """
            use sfdisk to change partition type.
            First try with --part-type; if fails, fall back to -c
        """

        command_to_use = '--part-type'
        input = "sfdisk {0} {1} {2}".format(command_to_use, '-f' if suppress_message else '', option_str)
        err_code, output = shellutil.run_get_output(input, chk_err=False, log_cmd=True)

        # fall back to -c
        if err_code != 0:
            logger.info("sfdisk with --part-type failed [{0}], retrying with -c", err_code)
            command_to_use = '-c'
            input = "sfdisk {0} {1} {2}".format(command_to_use, '-f' if suppress_message else '', option_str)
            err_code, output = shellutil.run_get_output(input, log_cmd=True)

        if err_code == 0:
            logger.info('{0} succeeded',
                        input)
        else:
            logger.error('{0} failed [{1}: {2}]',
                         input,
                         err_code,
                         output)

        return err_code, output

    @staticmethod
    def get_mount_string(mount_options, partition, mount_point):
        if mount_options is not None:
            return 'mount -o {0} {1} {2}'.format(mount_options,
                                                 partition,
                                                 mount_point)
        else:
            return 'mount {0} {1}'.format(partition, mount_point)

    def create_swap_space(self, mount_point, size_mb):
        size_kb = size_mb * 1024
        size = size_kb * 1024
        swapfile = os.path.join(mount_point, 'swapfile')
        swaplist = shellutil.run_get_output("swapon -s")[1]

        if swapfile in swaplist \
                and os.path.isfile(swapfile) \
                and os.path.getsize(swapfile) == size:
            logger.info("Swap already enabled")
            return

        if os.path.isfile(swapfile) and os.path.getsize(swapfile) != size:
            logger.info("Remove old swap file")
            shellutil.run("swapoff -a", chk_err=False)
            os.remove(swapfile)

        if not os.path.isfile(swapfile):
            logger.info("Create swap file")
            self.mkfile(swapfile, size_kb * 1024)
            shellutil.run("mkswap {0}".format(swapfile))
        if shellutil.run("swapon {0}".format(swapfile)):
            raise ResourceDiskError("{0}".format(swapfile))
        logger.info("Enabled {0}KB of swap at {1}".format(size_kb, swapfile))

    def mkfile(self, filename, nbytes):
        """
        Create a non-sparse file of that size. Deletes and replaces existing
        file.

        To allow efficient execution, fallocate will be tried first. This
        includes
        ``os.posix_fallocate`` on Python 3.3+ (unix) and the ``fallocate``
        command
        in the popular ``util-linux{,-ng}`` package.

        A dd fallback will be tried too. When size < 64M, perform
        single-pass dd.
        Otherwise do two-pass dd.
        """

        if not isinstance(nbytes, int):
            nbytes = int(nbytes)

        if nbytes <= 0:
            raise ResourceDiskError("Invalid swap size [{0}]".format(nbytes))

        if os.path.isfile(filename):
            os.remove(filename)

        # If file system is xfs, use dd right away as we have been reported that
        # swap enabling fails in xfs fs when disk space is allocated with fallocate
        ret = 0
        fn_sh = shellutil.quote((filename,))
        if self.fs != 'xfs':
            # os.posix_fallocate
            if sys.version_info >= (3, 3):
                # Probable errors:
                #  - OSError: Seen on Cygwin, libc notimpl?
                #  - AttributeError: What if someone runs this under...
                with open(filename, 'w') as f:
                    try:
                        os.posix_fallocate(f.fileno(), 0, nbytes)
                        return 0
                    except:
                        # Not confident with this thing, just keep trying...
                        pass

            # fallocate command
            ret = shellutil.run(
                u"umask 0077 && fallocate -l {0} {1}".format(nbytes, fn_sh))
            if ret == 0:
                return ret

            logger.info("fallocate unsuccessful, falling back to dd")

        # dd fallback
        dd_maxbs = 64 * 1024 ** 2
        dd_cmd = "umask 0077 && dd if=/dev/zero bs={0} count={1} " \
                 "conv=notrunc of={2}"

        blocks = int(nbytes / dd_maxbs)
        if blocks > 0:
            ret = shellutil.run(dd_cmd.format(dd_maxbs, blocks, fn_sh)) << 8

        remains = int(nbytes % dd_maxbs)
        if remains > 0:
            ret += shellutil.run(dd_cmd.format(remains, 1, fn_sh))

        if ret == 0:
            logger.info("dd successful")
        else:
            logger.error("dd unsuccessful")

        return ret
