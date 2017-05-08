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

import glob
import random
import string
import tempfile
import uuid

import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.future import ustr
from tests.tools import *


class TestFileOperations(AgentTestCase):

    def test_read_write_file(self):
        test_file=os.path.join(self.tmp_dir, self.test_file)
        content = ustr(uuid.uuid4())
        fileutil.write_file(test_file, content)

        content_read = fileutil.read_file(test_file)
        self.assertEquals(content, content_read)
        os.remove(test_file)
    
    def test_rw_utf8_file(self):
        test_file=os.path.join(self.tmp_dir, self.test_file)
        content = u"\u6211"
        fileutil.write_file(test_file, content, encoding="utf-8")

        content_read = fileutil.read_file(test_file)
        self.assertEquals(content, content_read)
        os.remove(test_file)

    def test_remove_bom(self):
        test_file=os.path.join(self.tmp_dir, self.test_file)
        data = b'\xef\xbb\xbfhehe'
        fileutil.write_file(test_file, data, asbin=True)
        data = fileutil.read_file(test_file, remove_bom=True)
        self.assertNotEquals(0xbb, ord(data[0]))
   
    def test_append_file(self):
        test_file=os.path.join(self.tmp_dir, self.test_file)
        content = ustr(uuid.uuid4())
        fileutil.append_file(test_file, content)

        content_read = fileutil.read_file(test_file)
        self.assertEquals(content, content_read)

        os.remove(test_file)

    def test_get_last_path_element(self):
        filepath = '/tmp/abc.def'
        filename = fileutil.base_name(filepath)
        self.assertEquals('abc.def', filename)

        filepath = '/tmp/abc'
        filename = fileutil.base_name(filepath)
        self.assertEquals('abc', filename)

    def test_remove_files(self):
        random_word = lambda : ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

        #Create 10 test files
        test_file = os.path.join(self.tmp_dir, self.test_file)
        test_file2 = os.path.join(self.tmp_dir, 'another_file')
        test_files = [test_file + random_word() for _ in range(5)] + \
                     [test_file2 + random_word() for _ in range(5)]
        for file in test_files:
            open(file, 'a').close()

        #Remove files using fileutil.rm_files
        test_file_pattern = test_file + '*'
        test_file_pattern2 = test_file2 + '*'
        fileutil.rm_files(test_file_pattern, test_file_pattern2)

        self.assertEqual(0, len(glob.glob(os.path.join(self.tmp_dir, test_file_pattern))))
        self.assertEqual(0, len(glob.glob(os.path.join(self.tmp_dir, test_file_pattern2))))

    def test_remove_dirs(self):
        dirs = []
        for n in range(0,5):
            dirs.append(tempfile.mkdtemp())
        for d in dirs:
            for n in range(0, random.choice(range(0,10))):
                fileutil.write_file(os.path.join(d, "test"+str(n)), "content")
            for n in range(0, random.choice(range(0,10))):
                dd = os.path.join(d, "testd"+str(n))
                os.mkdir(dd)
                for nn in range(0, random.choice(range(0,10))):
                    os.symlink(dd, os.path.join(dd, "sym"+str(nn)))
            for n in range(0, random.choice(range(0,10))):
                os.symlink(d, os.path.join(d, "sym"+str(n)))

        fileutil.rm_dirs(*dirs)

        for d in dirs:
            self.assertEqual(len(os.listdir(d)), 0)

    def test_get_all_files(self):
        random_word = lambda: ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

        # Create 10 test files at the root dir and 10 other in the sub dir
        test_file = os.path.join(self.tmp_dir, self.test_file)
        test_file2 = os.path.join(self.tmp_dir, 'another_file')
        expected_files = [test_file + random_word() for _ in range(5)] + \
                     [test_file2 + random_word() for _ in range(5)]

        test_subdir = os.path.join(self.tmp_dir, 'test_dir')
        os.mkdir(test_subdir)
        test_file_in_subdir = os.path.join(test_subdir, self.test_file)
        test_file_in_subdir2 = os.path.join(test_subdir, 'another_file')
        expected_files.extend([test_file_in_subdir + random_word() for _ in range(5)] + \
                     [test_file_in_subdir2 + random_word() for _ in range(5)])

        for file in expected_files:
            open(file, 'a').close()

        # Get All files using fileutil.get_all_files
        actual_files = fileutil.get_all_files(self.tmp_dir)

        self.assertEqual(set(expected_files), set(actual_files))

    @patch('os.path.isfile')
    def test_update_conf_file(self, _):
        new_file = "\
DEVICE=eth0\n\
ONBOOT=yes\n\
BOOTPROTO=dhcp\n\
TYPE=Ethernet\n\
USERCTL=no\n\
PEERDNS=yes\n\
IPV6INIT=no\n\
NM_CONTROLLED=yes\n"

        existing_file = "\
DEVICE=eth0\n\
ONBOOT=yes\n\
BOOTPROTO=dhcp\n\
TYPE=Ethernet\n\
DHCP_HOSTNAME=existing\n\
USERCTL=no\n\
PEERDNS=yes\n\
IPV6INIT=no\n\
NM_CONTROLLED=yes\n"

        bad_file = "\
DEVICE=eth0\n\
ONBOOT=yes\n\
BOOTPROTO=dhcp\n\
TYPE=Ethernet\n\
USERCTL=no\n\
PEERDNS=yes\n\
IPV6INIT=no\n\
NM_CONTROLLED=yes\n\
DHCP_HOSTNAME=no_new_line"

        updated_file = "\
DEVICE=eth0\n\
ONBOOT=yes\n\
BOOTPROTO=dhcp\n\
TYPE=Ethernet\n\
USERCTL=no\n\
PEERDNS=yes\n\
IPV6INIT=no\n\
NM_CONTROLLED=yes\n\
DHCP_HOSTNAME=test\n"

        path = 'path'
        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                fileutil.update_conf_file(path, 'DHCP_HOSTNAME', 'DHCP_HOSTNAME=test')
                patch_write.assert_called_once_with(path, updated_file)

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=existing_file):
                fileutil.update_conf_file(path, 'DHCP_HOSTNAME', 'DHCP_HOSTNAME=test')
                patch_write.assert_called_once_with(path, updated_file)

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=bad_file):
                fileutil.update_conf_file(path, 'DHCP_HOSTNAME', 'DHCP_HOSTNAME=test')
                patch_write.assert_called_once_with(path, updated_file)

if __name__ == '__main__':
    unittest.main()
