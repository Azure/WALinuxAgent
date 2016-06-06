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
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.utils.textutil import Version

class TestTextUtil(AgentTestCase):
    def test_get_password_hash(self):
        password_hash = textutil.gen_password_hash("asdf", 6, 10)
        self.assertNotEquals(None, password_hash)
        password_hash = textutil.gen_password_hash("asdf", 6, 0)
        self.assertNotEquals(None, password_hash)

    def test_remove_bom(self):
        #Test bom could be removed
        data = ustr(b'\xef\xbb\xbfhehe', encoding='utf-8')
        data = textutil.remove_bom(data)
        self.assertNotEquals(0xbb, data[0])
        
        #Test string without BOM is not affected
        data = u"hehe"
        data = textutil.remove_bom(data)
        self.assertEquals(u"h", data[0])

    def test_version_compare(self):
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

    def test_get_bytes_from_pem(self):
        content = ("-----BEGIN CERTIFICATE-----\n"
                   "certificate\n"
                   "-----END CERTIFICATE----\n")
        base64_bytes = textutil.get_bytes_from_pem(content)
        self.assertEquals("certificate", base64_bytes)


        content = ("-----BEGIN PRIVATE KEY-----\n"
                   "private key\n"
                   "-----END PRIVATE Key-----\n")
        base64_bytes = textutil.get_bytes_from_pem(content)
        self.assertEquals("private key", base64_bytes)
        
if __name__ == '__main__':
    unittest.main()
