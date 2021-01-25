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

import hashlib
import os
import unittest
from distutils.version import LooseVersion as Version  # pylint: disable=no-name-in-module,import-error

import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.future import ustr
from tests.tools import AgentTestCase


class TestTextUtil(AgentTestCase):
    def test_get_password_hash(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_passwords.txt'), 'rb') as in_file:
            for data in in_file:
                # Remove bom on bytes data before it is converted into string.
                data = textutil.remove_bom(data)
                data = ustr(data, encoding='utf-8')
                password_hash = textutil.gen_password_hash(data, 6, 10)
                self.assertNotEqual(None, password_hash)

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
        self.assertNotEqual(0xbb, data[0])

        #bom is comprised of a sequence of three bytes and ff length of the input is shorter
        # than three bytes, remove_bom should not do anything
        data = u"\xa7"
        data = textutil.remove_bom(data)
        self.assertEqual(data, data[0])

        data = u"\xa7\xef"
        data = textutil.remove_bom(data)
        self.assertEqual(u"\xa7", data[0])
        self.assertEqual(u"\xef", data[1])

        #Test string without BOM is not affected
        data = u"hehe"
        data = textutil.remove_bom(data)
        self.assertEqual(u"h", data[0])

        data = u""
        data = textutil.remove_bom(data)
        self.assertEqual(u"", data)

        data = u"  "
        data = textutil.remove_bom(data)
        self.assertEqual(u"  ", data)

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
        self.assertEqual("certificate", base64_bytes)


        content = ("-----BEGIN PRIVATE KEY-----\n"
                   "private key\n"
                   "-----END PRIVATE Key-----\n")
        base64_bytes = textutil.get_bytes_from_pem(content)
        self.assertEqual("private key", base64_bytes)

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

    def test_empty_strings(self):
        self.assertTrue(textutil.is_str_none_or_whitespace(None))
        self.assertTrue(textutil.is_str_none_or_whitespace(' '))
        self.assertTrue(textutil.is_str_none_or_whitespace('\t'))
        self.assertTrue(textutil.is_str_none_or_whitespace('\n'))
        self.assertTrue(textutil.is_str_none_or_whitespace(' \t'))
        self.assertTrue(textutil.is_str_none_or_whitespace(' \r\n'))

        self.assertTrue(textutil.is_str_empty(None))
        self.assertTrue(textutil.is_str_empty(' '))
        self.assertTrue(textutil.is_str_empty('\t'))
        self.assertTrue(textutil.is_str_empty('\n'))
        self.assertTrue(textutil.is_str_empty(' \t'))
        self.assertTrue(textutil.is_str_empty(' \r\n'))

        self.assertFalse(textutil.is_str_none_or_whitespace(u' \x01 '))
        self.assertFalse(textutil.is_str_none_or_whitespace(u'foo'))
        self.assertFalse(textutil.is_str_none_or_whitespace('bar'))

        self.assertFalse(textutil.is_str_empty(u' \x01 '))
        self.assertFalse(textutil.is_str_empty(u'foo'))
        self.assertFalse(textutil.is_str_empty('bar'))

        hex_null_1 = u'\x00'
        hex_null_2 = u' \x00 '

        self.assertFalse(textutil.is_str_none_or_whitespace(hex_null_1))
        self.assertFalse(textutil.is_str_none_or_whitespace(hex_null_2))

        self.assertTrue(textutil.is_str_empty(hex_null_1))
        self.assertTrue(textutil.is_str_empty(hex_null_2))

        self.assertNotEqual(textutil.is_str_none_or_whitespace(hex_null_1), textutil.is_str_empty(hex_null_1))
        self.assertNotEqual(textutil.is_str_none_or_whitespace(hex_null_2), textutil.is_str_empty(hex_null_2))

    def test_format_memory_value(self):
        """
        Test formatting of memory amounts into human-readable units
        """
        self.assertEqual(2048, textutil.format_memory_value('kilobytes', 2))
        self.assertEqual(0, textutil.format_memory_value('kilobytes', 0))
        self.assertEqual(2048000, textutil.format_memory_value('kilobytes', 2000))
        self.assertEqual(2048 * 1024, textutil.format_memory_value('megabytes', 2))
        self.assertEqual((1024 + 512) * 1024 * 1024, textutil.format_memory_value('gigabytes', 1.5))
        self.assertRaises(ValueError, textutil.format_memory_value, 'KiloBytes', 1)
        self.assertRaises(TypeError, textutil.format_memory_value, 'bytes', None)


if __name__ == '__main__':
    unittest.main()
