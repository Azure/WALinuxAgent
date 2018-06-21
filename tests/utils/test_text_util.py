# Copyright 2018 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

from distutils.version import LooseVersion as Version
from tests.tools import *

import hashlib

import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.future import ustr


class TestTextUtil(AgentTestCase):
    def test_get_password_hash(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_passwords.txt'), 'rb') as in_file:
            for data in in_file:
                # Remove bom on bytes data before it is converted into string.
                data = textutil.remove_bom(data)
                data = ustr(data, encoding='utf-8')
                password_hash = textutil.gen_password_hash(data, 6, 10)
                self.assertNotEquals(None, password_hash)

    def test_replace_non_ascii(self):
        data = ustr(b'\xef\xbb\xbfhehe', encoding='utf-8')
        self.assertEqual('hehe', textutil.replace_non_ascii(data))

        data = "abcd\xa0e\xf0fghijk\xbblm"
        self.assertEqual("abcdefghijklm", textutil.replace_non_ascii(data))

        data = "abcd\xa0e\xf0fghijk\xbblm"
        self.assertEqual("abcdXeXfghijkXlm",
            textutil.replace_non_ascii(data, replace_char='X'))

        self.assertEqual('', textutil.replace_non_ascii(None))

    def test_remove_bom(self):
        #Test bom could be removed
        data = ustr(b'\xef\xbb\xbfhehe', encoding='utf-8')
        data = textutil.remove_bom(data)
        self.assertNotEquals(0xbb, data[0])

        #bom is comprised of a sequence of three bytes and ff length of the input is shorter
        # than three bytes, remove_bom should not do anything
        data = u"\xa7"
        data = textutil.remove_bom(data)
        self.assertEquals(data, data[0])

        data = u"\xa7\xef"
        data = textutil.remove_bom(data)
        self.assertEquals(u"\xa7", data[0])
        self.assertEquals(u"\xef", data[1])

        #Test string without BOM is not affected
        data = u"hehe"
        data = textutil.remove_bom(data)
        self.assertEquals(u"h", data[0])

        data = u""
        data = textutil.remove_bom(data)
        self.assertEquals(u"", data)

        data = u"  "
        data = textutil.remove_bom(data)
        self.assertEquals(u"  ", data)

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

    def test_swap_hexstring(self):
        data = [
            ['12', 1, '21'],
            ['12', 2, '12'],
            ['12', 3, '012'],
            ['12', 4, '0012'],

            ['123', 1, '321'],
            ['123', 2, '2301'],
            ['123', 3, '123'],
            ['123', 4, '0123'],

            ['1234', 1, '4321'],
            ['1234', 2, '3412'],
            ['1234', 3, '234001'],
            ['1234', 4, '1234'],

            ['abcdef12', 1, '21fedcba'],
            ['abcdef12', 2, '12efcdab'],
            ['abcdef12', 3, 'f12cde0ab'],
            ['abcdef12', 4, 'ef12abcd'],

            ['aBcdEf12', 1, '21fEdcBa'],
            ['aBcdEf12', 2, '12EfcdaB'],
            ['aBcdEf12', 3, 'f12cdE0aB'],
            ['aBcdEf12', 4, 'Ef12aBcd']
        ]

        for t in data:
            self.assertEqual(t[2], textutil.swap_hexstring(t[0], width=t[1]))

    def test_compress(self):
        result = textutil.compress('[stdout]\nHello World\n\n[stderr]\n\n')
        self.assertEqual('eJyLLi5JyS8tieXySM3JyVcIzy/KSeHiigaKphYVxXJxAQDAYQr2', result)

    def test_hash_empty_list(self):
        result = textutil.hash_strings([])
        self.assertEqual(b'\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t', result)

    def test_hash_list(self):
        test_list = ["abc", "123"]
        result_from_list = textutil.hash_strings(test_list)

        test_string = "".join(test_list)
        hash_from_string = hashlib.sha1()
        hash_from_string.update(test_string.encode())

        self.assertEqual(result_from_list, hash_from_string.digest())
        self.assertEqual(hash_from_string.hexdigest(), '6367c48dd193d56ea7b0baad25b19455e529f5ee')


if __name__ == '__main__':
    unittest.main()
