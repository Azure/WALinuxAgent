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
import uuid
import unittest
import os
import sys
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.utils.fileutil as fileutil

class TestFileOperations(AgentTestCase):
    def test_read_write_file(self):
        test_file=os.path.join(self.tmp_dir, 'test_file')
        content = ustr(uuid.uuid4())
        fileutil.write_file(test_file, content)

        content_read = fileutil.read_file(test_file)
        self.assertEquals(content, content_read)
        os.remove(test_file)
    
    def test_rw_utf8_file(self):
        test_file=os.path.join(self.tmp_dir, 'test_file')
        content = u"\u6211"
        fileutil.write_file(test_file, content, encoding="utf-8")

        content_read = fileutil.read_file(test_file)
        self.assertEquals(content, content_read)
        os.remove(test_file)

    def test_remove_bom(self):
        test_file=os.path.join(self.tmp_dir, 'test_file')
        data = b'\xef\xbb\xbfhehe'
        fileutil.write_file(test_file, data, asbin=True)
        data = fileutil.read_file(test_file, remove_bom=True)
        self.assertNotEquals(0xbb, ord(data[0]))
   
    def test_append_file(self):
        test_file=os.path.join(self.tmp_dir, 'test_file')
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

if __name__ == '__main__':
    unittest.main()
