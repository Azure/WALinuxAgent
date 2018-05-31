# Copyright Microsoft Corporation
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

from datetime import datetime, timedelta, tzinfo
from azurelinuxagent.common.protocol import get_protocol_util
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.exception import CryptError
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler, REMOTE_USR_EXPIRATION_FORMAT, MAX_TRY_ATTEMPT
from tests.common.osutil.mock_osutil import MockOSUtil
from tests.protocol.mockwiredata import WireProtocolData, DATA_FILE
from tests.tools import *

class TestRemoteAccessHandler(AgentTestCase):
    
    def test_add_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "abc@123"
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = self.encrypt_string(tstpassword)
        rah.add_user(tstuser, pwd, expiration)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[1], tstpassword)
        self.assertEqual(actual_user[7], (expiration - datetime.utcnow() + timedelta(days=1)).days)
        self.assertEqual(actual_user[4], "JIT Account")
            
    def test_delete_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "abc@123"
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = self.encrypt_string(tstpassword)
        rah.add_user(tstuser, pwd, expiration)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        rah.delete_user(tstuser)
        self.assertFalse(tstuser in os_util.all_users)
    
    def test_handle_new_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()  
        tstpassword = "abc@123"    
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        expiration = (datetime.utcnow() + timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        remote_access.user_list.users[0].encrypted_password = self.encrypt_string(tstpassword)
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(remote_access.user_list.users[0].name in os_util.all_users)
        actual_user = os_util.all_users[remote_access.user_list.users[0].name]
        self.assertEqual(actual_user[1], tstpassword)
        self.assertEqual(actual_user[7], (datetime.strptime(expiration, REMOTE_USR_EXPIRATION_FORMAT) - datetime.utcnow() + timedelta(days=1)).days)
        self.assertEqual(actual_user[4], "JIT Account")

    def test_do_not_add_expired_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()      
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        expiration = (datetime.utcnow() - timedelta(days=2)).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertFalse("testAccount" in os_util.all_users)

    def test_error_add_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = "bad password"
        attempts = rah.add_user(tstuser, pwd, expiration, throttle=0)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertFalse(tstuser in os_util.all_users)      
        self.assertEqual(5, attempts)      

    def encrypt_string(self, secret):
        prv_key, pub_key, cert = self.create_keys()
        cache_file = os.path.join(self.tmp_dir, "encrypted.enc")
        cmd = "echo -n {0} | openssl smime -encrypt -binary -des -out {2} -outform DER {1}".format(secret, cert, cache_file)
        rc, output = shellutil.run_get_output(cmd)

        try:
            with open(cache_file, "rb") as data:
                encrypted_text = base64.b64encode(data.read())
        except Exception as e:
            self.fail("Failed to encrypt string.  This should be a test only error. {0}".format(str(e)))
        return encrypted_text
    
    def create_keys(self):
        private_key = os.path.join(self.tmp_dir, "TransportPrivate.pem")
        public_key = os.path.join(self.tmp_dir, "TransportPublic.pem")
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
