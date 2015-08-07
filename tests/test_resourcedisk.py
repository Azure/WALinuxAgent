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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import tests.env
from tests.tools import *
import unittest
import azurelinuxagent.distro.default.resourceDisk as rdh
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import OSUTIL

#logger.LoggerInit("/dev/null", "/dev/stdout")

gpt_output_sample="""
Model: Msft Virtual Disk (scsi)
Disk /dev/sda: 32.2GB
Sector size (logical/physical): 512B/4096B
Partition Table: gpt

Number  Start   End     Size    Type     File system  Flags
 1      2097kB  29.4GB  29.4GB  primary  ext4         boot
 2      2097kB  29.4GB  29.4GB  primary  ext4         boot
"""

class TestResourceDisk(unittest.TestCase):

    @mock(rdh.OSUTIL, 'device_for_ide_port', MockFunc(retval='foo'))
    @mock(rdh.shellutil, 'run_get_output', MockFunc(retval=(0, gpt_output_sample)))
    @mock(rdh.shellutil, 'run', MockFunc(retval=0))
    def test_mountGPT(self):
        handler = rdh.ResourceDiskHandler()
        handler.mount_resource_disk('/tmp/foo', 'ext4')

    @mock(rdh.OSUTIL, 'device_for_ide_port', MockFunc(retval='foo'))
    @mock(rdh.shellutil, 'run_get_output', MockFunc(retval=(0, "")))
    @mock(rdh.shellutil, 'run', MockFunc(retval=0))
    def test_mountMBR(self):
        handler = rdh.ResourceDiskHandler()
        handler.mount_resource_disk('/tmp/foo', 'ext4')

    @mock(rdh.shellutil, 'run', MockFunc(retval=0))
    def test_createSwapSpace(self):
        handler = rdh.ResourceDiskHandler()
        handler.create_swap_space('/tmp/foo', 512)

if __name__ == '__main__':
    unittest.main()
