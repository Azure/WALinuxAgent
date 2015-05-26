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

import env
from tests.tools import *
import unittest
import azureguestagent.handler.default.resourceDiskHandler as rdh
import azureguestagent.logger as logger
from azureguestagent.utils.osutil import CurrOSUtil

#logger.LoggerInit("/dev/null", "/dev/stdout")

MockGPTOutput="""
Model: Msft Virtual Disk (scsi)
Disk /dev/sda: 32.2GB
Sector size (logical/physical): 512B/4096B
Partition Table: gpt

Number  Start   End     Size    Type     File system  Flags
 1      2097kB  29.4GB  29.4GB  primary  ext4         boot
 2      2097kB  29.4GB  29.4GB  primary  ext4         boot
"""

class TestResourceDisk(unittest.TestCase):

    @Mockup(rdh.CurrOSUtil, 'DeviceForIdePort', MockFunc(retval='foo'))
    @Mockup(rdh.shellutil, 'RunGetOutput', MockFunc(retval=(0, MockGPTOutput)))
    @Mockup(rdh.shellutil, 'Run', MockFunc(retval=0))
    def test_mountGPT(self):
        handler = rdh.ResourceDiskHandler()
        handler.mountResourceDisk('/tmp/foo', 'ext4')

    @Mockup(rdh.CurrOSUtil, 'DeviceForIdePort', MockFunc(retval='foo'))
    @Mockup(rdh.shellutil, 'RunGetOutput', MockFunc(retval=(0, "")))
    @Mockup(rdh.shellutil, 'Run', MockFunc(retval=0))
    def test_mountMBR(self):
        handler = rdh.ResourceDiskHandler()
        handler.mountResourceDisk('/tmp/foo', 'ext4')

    @Mockup(rdh.shellutil, 'Run', MockFunc(retval=0))
    def test_createSwapSpace(self):
        handler = rdh.ResourceDiskHandler()
        handler.createSwapSpace('/tmp/foo', 512)

if __name__ == '__main__':
    unittest.main()
