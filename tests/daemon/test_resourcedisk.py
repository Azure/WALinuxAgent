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

from tests.tools import *
from azurelinuxagent.common.exception import *
from azurelinuxagent.daemon import *
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class TestResourceDisk(AgentTestCase):
    def test_mount_flags_empty(self):
        partition = '/dev/sdb1'
        mountpoint = '/mnt/resource'
        options = None
        expected = 'mount /dev/sdb1 /mnt/resource'
        rdh = ResourceDiskHandler()
        mount_string = rdh.get_mount_string(options, partition, mountpoint)
        self.assertEqual(expected, mount_string)

    def test_mount_flags_many(self):
        partition = '/dev/sdb1'
        mountpoint = '/mnt/resource'
        options = 'noexec,noguid,nodev'
        expected = 'mount -o noexec,noguid,nodev /dev/sdb1 /mnt/resource'
        rdh = ResourceDiskHandler()
        mount_string = rdh.get_mount_string(options, partition, mountpoint)
        self.assertEqual(expected, mount_string)

if __name__ == '__main__':
    unittest.main()
