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

import unittest
import tempfile
import os
from env import waagent

sample_mount_list = """\
/dev/sda1 on / type ext4 (rw)
proc on /proc type proc (rw)
sysfs on /sys type sysfs (rw)
devpts on /dev/pts type devpts (rw,gid=5,mode=620)
tmpfs on /dev/shm type tmpfs (rw,rootcontext="system_u:object_r:tmpfs_t:s0")
none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)
/dev/sdb1 on /mnt/resource type ext4 (rw)
"""

device_name="/dev/sdb"

class TestWAAgentUtils(unittest.TestCase):
    
    def test_get_mount_point(self):
        normal = sample_mount_list
        mp = waagent.GetMountPoint(normal, device_name)
        self.assertEqual(mp, '/mnt/resource')

        null = None
        mp = waagent.GetMountPoint(null, device_name)
        self.assertEqual(mp, None)

        malformed = 'asdfasdfasdfa aasdf'
        mp = waagent.GetMountPoint(malformed, device_name)
        self.assertEqual(mp, None)

    def test_replace_in_file_found(self):
        tmpfilename = tempfile.mkstemp('', 'tmp', None, True)[1]
        try:
            tmpfile = open(tmpfilename, 'w')
            tmpfile.write('Replace Me')
            tmpfile.close()

            result = waagent.ReplaceStringInFile(tmpfilename, r'c. ', 'ced ')

            tmpfile = open(tmpfilename, 'r')
            newcontents = tmpfile.read();
            tmpfile.close()

            self.assertEqual('Replaced Me', str(newcontents))
        finally:
            os.remove(tmpfilename)

    def test_replace_in_file_not_found(self):
        tmpfilename = tempfile.mkstemp('', 'tmp', None, True)[1]
        try:
            tmpfile = open(tmpfilename, 'w')
            tmpfile.write('Replace Me')
            tmpfile.close()

            result = waagent.ReplaceStringInFile(tmpfilename, r'not here ', 'ced ')

            tmpfile = open(tmpfilename, 'r')
            newcontents = tmpfile.read();
            tmpfile.close()

            self.assertEqual('Replace Me', str(newcontents))
        finally:
            os.remove(tmpfilename)

if __name__ == '__main__':
    unittest.main()
