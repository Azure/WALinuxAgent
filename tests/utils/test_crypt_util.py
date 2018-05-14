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

    privateKeySuffix = "PrvTEST.pem"
    publicKeySuffix = "PubTEST.pem"
    encryptedCacheFile = None

    def encryptString(self, secret, pubKey):
        self.encryptedCacheFile = os.path.join(self.tmp_dir, "encrypted.enc")
        cmd = "echo {0} | openssl smime -encrypt -binary -des -out {2} -outform DER {1}".format(secret, pubKey, self.encryptedCacheFile)
        shellutil.run_get_output(cmd)

        try:
            with open(self.encryptedCacheFile, "rb") as data:
                encryptedText = base64.b64encode(data.read())
        except Exception as e:
            self.fail("Failed to encrypt string.  This should be a test only error. {0}".format(str(e)))
            pass
        return encryptedText

    
    def createKeys(self, baseKeyName):
        privateKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.privateKeySuffix))
        publicKey = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, self.publicKeySuffix))
        cert = os.path.join(self.tmp_dir, "{0}{1}".format(baseKeyName, ".cert"))
        try:
            cryptutl = CryptUtil(conf.get_openssl_cmd())
            cryptutl.gen_transport_cert(privateKey, cert)
            pubKeyText = cryptutl.get_pubkey_from_prv(privateKey)
            with open(publicKey, "w") as pk:
                pk.write(pubKeyText)
        except Exception as e:
            self.fail("Error creating keys.  Test setup error.  {0}".format(str(e)))

        return privateKey, publicKey, cert

    def test_decrypt_encrypted_text(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        cert = keys[2]
        encryptedString = self.encryptString(secret, cert)

        crypto = CryptUtil(conf.get_openssl_cmd())
        decryptedString = crypto.decryptSecret(encryptedString, prvKey, "temp.dat")
        self.assertEquals(secret, decryptedString, "decrypted string does not match expected")

    def test_decrypt_encrypted_text_missing_private_key(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        cert = keys[2]
        encryptedString = self.encryptString(secret, cert)

        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decryptSecret(encryptedString, "abc" + prvKey, "temp.dat")
        except CryptError as e:
            self.assertTrue(("Error opening signing key file" in str(e)), "Expected exception not found.")
            return
        self.fail("Expected Excetpion, but none returned.")
    
    def test_decrypt_encrypted_text_wrong_private_key(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        cert = keys[2]
        encryptedString = self.encryptString(secret, cert)
        keys2 = self.createKeys("wrong" + baseKeyName)
        w_prvKey = keys2[0]
        w_cert = keys2[2]
        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decryptSecret(encryptedString, w_prvKey, "temp.dat")
        except CryptError as e:
            self.assertTrue(("Error decrypting file" in str(e)), "Expected exception not found. {0}".format(str(e)))
            return
        self.fail("Expected Excetpion, but none returned.")

    def test_decrypt_encrypted_text_text_not_encrypted(self):
        baseKeyName = "test"
        secret = "abc@123"
        keys = self.createKeys(baseKeyName)
        prvKey = keys[0]
        cert = keys[2]
        encryptedString = "abc@123"        
        crypto = CryptUtil(conf.get_openssl_cmd())
        try:
            crypto.decryptSecret(encryptedString, prvKey, "temp.dat")
        except Exception as e:
            self.assertTrue(("Incorrect padding" in str(e)), "Expected exception not found. {0}".format(str(e)))
            return
        self.fail("Expected Excetpion, but none returned.")

if __name__ == '__main__':
    unittest.main()
