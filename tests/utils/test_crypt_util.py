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
import errno as errno
import glob
import random
import string
import tempfile
import uuid

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.exception import CryptError
from tests.tools import *

class TestCryptoUtilOperations(AgentTestCase):    
    def encrypt_string(self, secret, pubKey, cache_file=None):
        if cache_file is None:
            cache_file = os.path.join(self.tmp_dir, "encrypted.enc")
        cmd = "echo -n {0} | openssl smime -encrypt -binary -des -out {2} -outform DER {1}".format(secret, pubKey, cache_file)
        shellutil.run_get_output(cmd)

        try:
            with open(cache_file, "rb") as data:
                encrypted_text = base64.b64encode(data.read())
        except Exception as e:
            self.fail("Failed to encrypt string.  This should be a test only error. {0}".format(str(e)))
        return encrypted_text
    
    def create_keys(self, private_key=None, public_key=None, cert=None):
        if private_key is None:
            private_key = os.path.join(self.tmp_dir, "TransportPrivate.pem")
        if public_key is None:
            public_key = os.path.join(self.tmp_dir, "TransportPublic.pem")
        if cert is None:
            cert = os.path.join(self.tmp_dir, "Transport.cert")
        try:
            crypto = CryptUtil(conf.get_openssl_cmd())
            crypto.gen_transport_cert(private_key, cert)
            pub_key_text = crypto.get_pubkey_from_prv(private_key)
            with open(public_key, "w") as pk:
                pk.write(pub_key_text)
        except Exception as e:
            self.fail("Error creating keys.  Test setup error.  {0}".format(str(e)))

        return private_key, public_key, cert
    def test_decrypt_encrypted_text(self):
        base_key_name = "test"
        secret = "abc@123"
        prv_key, pub_key, cert = self.create_keys()
        encrypted_string = self.encrypt_string(secret, cert)

        crypto = CryptUtil(conf.get_openssl_cmd())
        decrypted_string = crypto.decrypt_secret(encrypted_string, prv_key, "pwd.dat", None)
        self.assertEquals(secret, decrypted_string, "decrypted string does not match expected")

    def test_decrypt_encrypted_text_missing_private_key(self):
        base_key_name = "test"
        secret = "abc@123"
        prv_key, pub_key, cert = self.create_keys()
        encrypted_string = self.encrypt_string(secret, cert)

        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decrypt_secret(encrypted_string, "abc" + prv_key, "pwd.dat", None)
        except CryptError as e:
            self.assertTrue(("Error opening signing key file" in str(e)), "Expected exception not found.")
            return
        self.fail("Expected Excetpion, but none returned.")
    
    def test_decrypt_encrypted_text_wrong_private_key(self):
        base_key_name = "test"
        secret = "abc@123"
        prv_key, pub_key, cert = self.create_keys()
        encrypted_string = self.encrypt_string(secret, cert)
        w_prv = os.path.join(self.tmp_dir, "wrong_private_key.pem")
        w_pub = os.path.join(self.tmp_dir, "wrong_public_key.pem")
        w_cert = os.path.join(self.tmp_dir, "wrong_cert.cert")
        w_prv_key, w_pub_key, w_cert = self.create_keys(w_prv, w_pub, w_cert)
        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decrypt_secret(encrypted_string, w_prv_key, "pwd.dat", None)
        except CryptError as e:
            self.assertTrue(("Error decrypting file" in str(e)), "Expected exception not found. {0}".format(str(e)))
            return
        self.fail("Expected Excetpion, but none returned.")

    def test_decrypt_encrypted_text_text_not_encrypted(self):
        base_key_name = "test"
        prv_key, pub_key, cert = self.create_keys()
        encrypted_string = "abc@123"        
        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decrypt_secret(encrypted_string, prv_key, "pwd.dat", None)
        except Exception as e:
            self.assertTrue(("Incorrect padding" in str(e)), "Expected exception not found. {0}".format(str(e)))
            return
        self.fail("Expected Exception, but none returned.")

if __name__ == '__main__':
    unittest.main()
