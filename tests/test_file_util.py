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
import tests.tools as tools
import uuid
import unittest
import os
import azurelinuxagent.utils.fileutil as fileutil
import test

class TestFileOperations(unittest.TestCase):
    def test_get_set_file_contents(self):
        test_file='/tmp/test_file'
        content = str(uuid.uuid4())
        fileutil.write_file(test_file, content)
        self.assertTrue(tools.simple_file_grep(test_file, content))
        self.assertEquals(content, fileutil.read_file('/tmp/test_file'))
        os.remove(test_file)

    def test_append_file(self):
        test_file='/tmp/test_file2'
        content = str(uuid.uuid4())
        fileutil.append_file(test_file, content)
        self.assertTrue(tools.simple_file_grep(test_file, content))
        os.remove(test_file)

    def test_replace_file(self):
        test_file='/tmp/test_file3'
        old_content = str(uuid.uuid4())
        content = str(uuid.uuid4())
        with open(test_file, "a+") as F:
            F.write(old_content)
        fileutil.replace_file(test_file, content)
        self.assertFalse(tools.simple_file_grep(test_file, old_content))
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
