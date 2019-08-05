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

import base64
import binascii
import errno as errno
import glob
import random
import string
import subprocess
import sys
import tempfile
import uuid
import unittest

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.exception import CryptError
from azurelinuxagent.common.version import PY_VERSION_MAJOR
from tests.tools import *
from subprocess import CalledProcessError


def is_python_version_26():
    return sys.version_info[0] == 2 and sys.version_info[1] == 6


class TestCryptoUtilOperations(AgentTestCase):
    def test_decrypt_encrypted_text(self):
        encrypted_string = load_data("wire/encrypted.enc")
        prv_key = os.path.join(self.tmp_dir, "TransportPrivate.pem") 
        with open(prv_key, 'w+') as c:
            c.write(load_data("wire/sample.pem"))
        secret = ']aPPEv}uNg1FPnl?'
        crypto = CryptUtil(conf.get_openssl_cmd())
        decrypted_string = crypto.decrypt_secret(encrypted_string, prv_key)
        self.assertEquals(secret, decrypted_string, "decrypted string does not match expected")

    def test_decrypt_encrypted_text_missing_private_key(self):
        encrypted_string = load_data("wire/encrypted.enc")
        prv_key = os.path.join(self.tmp_dir, "TransportPrivate.pem")
        crypto = CryptUtil(conf.get_openssl_cmd())
        self.assertRaises(CryptError, crypto.decrypt_secret, encrypted_string, "abc" + prv_key)

    @skip_if_predicate_true(is_python_version_26, "Disabled on Python 2.6")
    def test_decrypt_encrypted_text_wrong_private_key(self):
        encrypted_string = load_data("wire/encrypted.enc")
        prv_key = os.path.join(self.tmp_dir, "wrong.pem")
        with open(prv_key, 'w+') as c:
            c.write(load_data("wire/trans_prv"))
        crypto = CryptUtil(conf.get_openssl_cmd())
        self.assertRaises(CryptError, crypto.decrypt_secret, encrypted_string, prv_key)

    def test_decrypt_encrypted_text_text_not_encrypted(self):
        encrypted_string = "abc@123"
        prv_key = os.path.join(self.tmp_dir, "TransportPrivate.pem")
        with open(prv_key, 'w+') as c:
            c.write(load_data("wire/sample.pem"))
        crypto = CryptUtil(conf.get_openssl_cmd())
        self.assertRaises(CryptError, crypto.decrypt_secret, encrypted_string, prv_key)


if __name__ == '__main__':
    unittest.main()
