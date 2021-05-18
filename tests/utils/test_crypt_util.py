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

import os
import unittest

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import CryptError
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from tests.tools import AgentTestCase, data_dir, load_data, is_python_version_26, skip_if_predicate_true


class TestCryptoUtilOperations(AgentTestCase):

    def test_decrypt_encrypted_text(self):
        encrypted_string = load_data("wire/encrypted.enc")
        prv_key = os.path.join(self.tmp_dir, "TransportPrivate.pem") 
        with open(prv_key, 'w+') as c:
            c.write(load_data("wire/sample.pem"))
        secret = ']aPPEv}uNg1FPnl?'
        crypto = CryptUtil(conf.get_openssl_cmd())
        decrypted_string = crypto.decrypt_secret(encrypted_string, prv_key)
        self.assertEqual(secret, decrypted_string, "decrypted string does not match expected")

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

    def test_get_pubkey_from_crt(self):
        crypto = CryptUtil(conf.get_openssl_cmd())
        prv_key = os.path.join(data_dir, "wire", "trans_prv")
        expected_pub_key = os.path.join(data_dir, "wire", "trans_pub")

        with open(expected_pub_key) as fh:
            self.assertEqual(fh.read(), crypto.get_pubkey_from_prv(prv_key))

    def test_get_pubkey_from_crt_invalid_file(self):
        crypto = CryptUtil(conf.get_openssl_cmd())
        prv_key = os.path.join(data_dir, "wire", "trans_prv_does_not_exist")

        self.assertRaises(IOError, crypto.get_pubkey_from_prv, prv_key)


if __name__ == '__main__':
    unittest.main()
