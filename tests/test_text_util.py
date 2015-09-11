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
import uuid
import unittest
import os
from azurelinuxagent.future import text
import azurelinuxagent.utils.textutil as textutil
from azurelinuxagent.utils.textutil import Version

class TestTextUtil(unittest.TestCase):
    def test_get_password_hash(self):
        password_hash = textutil.gen_password_hash("asdf", 6, 10)
        self.assertNotEquals(None, password_hash)
        password_hash = textutil.gen_password_hash("asdf", 6, 0)
        self.assertNotEquals(None, password_hash)

    def test_remove_bom(self):
        #Test bom could be removed
        data = text(b'\xef\xbb\xbfhehe', encoding='utf-8')
        data = textutil.remove_bom(data)
        self.assertNotEquals(0xbb, data[0])
        
        #Test string without BOM is not affected
        data = u"hehe"
        data = textutil.remove_bom(data)
        self.assertEquals(u"h", data[0])

    def test_version_compare(self) :
        self.assertTrue(Version("1.0") < Version("1.1"))
        self.assertTrue(Version("1.9") < Version("1.10"))
        self.assertTrue(Version("1.9.9") < Version("1.10.0"))
        self.assertTrue(Version("1.0.0.0") < Version("1.2.0.0"))

        self.assertTrue(Version("1.0") <= Version("1.1"))
        self.assertTrue(Version("1.1") > Version("1.0"))
        self.assertTrue(Version("1.1") >= Version("1.0"))

        self.assertTrue(Version("1.0") == Version("1.0"))
        self.assertTrue(Version("1.0") >= Version("1.0"))
        self.assertTrue(Version("1.0") <= Version("1.0"))

        self.assertTrue(Version("1.9") < "1.10")
        self.assertTrue("1.9" < Version("1.10"))
        
if __name__ == '__main__':
    unittest.main()
