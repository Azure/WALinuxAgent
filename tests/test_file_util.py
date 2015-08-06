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
import tests.tools as tools
import uuid
import unittest
import os
import sys
from azurelinuxagent.future import text
import azurelinuxagent.utils.fileutil as fileutil

class TestFileOperations(unittest.TestCase):
    def test_read_write_file(self):
        test_file='/tmp/test_file'
        content = text(uuid.uuid4())
        fileutil.write_file(test_file, content)
        self.assertTrue(tools.simple_file_grep(test_file, content))

        content_read = fileutil.read_file('/tmp/test_file')
        self.assertEquals(content, content_read)
        os.remove(test_file)
    
    def test_rw_utf8_file(self):
        test_file='/tmp/test_file3'
        content = "\u6211"
        fileutil.write_file(test_file, content, encoding="utf-8")
        self.assertTrue(tools.simple_file_grep(test_file, content))

        content_read = fileutil.read_file('/tmp/test_file3')
        self.assertEquals(content, content_read)
        os.remove(test_file)

    def test_remove_bom(self):
        test_file= '/tmp/test_file4'
        data = b'\xef\xbb\xbfhehe'
        fileutil.write_file(test_file, data, asbin=True)
        data = fileutil.read_file(test_file, remove_bom=True)
        self.assertNotEquals(0xbb, ord(data[0]))
   
    def test_append_file(self):
        test_file='/tmp/test_file2'
        content = text(uuid.uuid4())
        fileutil.append_file(test_file, content)
        self.assertTrue(tools.simple_file_grep(test_file, content))
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
