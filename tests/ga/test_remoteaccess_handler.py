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
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler, REMOTE_USR_EXPIRATION_FORMAT
from tests.utils.test_crypt_util import TestCryptoUtilOperations
from tests.common.osutil.mock_osutil import MockOSUtil
from tests.tools import *

class TestRemoteAccessHandler(AgentTestCase):
    
    prv_key = None
    pub_key = None
    cert = None

    def test_add_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "abc@123"
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = self.encrypt_password(tstpassword)
        rah.add_user(tstuser, pwd, expiration)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[1], tstpassword)
        self.assertEqual(actual_user[7], (expiration - datetime.utcnow() + timedelta(days=1)).days)
        self.assertEqual(actual_user[4], "JIT Account")
            
    def test_remove_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "abc@123"
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = self.encrypt_password(tstpassword)
        rah.add_user(tstuser, pwd, expiration)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        rah.remove_user(tstuser)
        self.assertFalse(tstuser in os_util.all_users)
    
    def test_handle_new_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()  
        tstpassword = "abc@123"    
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        expiration = (datetime.utcnow() + timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        remote_access.user_list.users[0].encrypted_password = self.encrypt_password(tstpassword)

        rah.handle_remote_access(remote_access)
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

        rah.handle_remote_access(remote_access)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertFalse("testAccount" in os_util.all_users)

    def encrypt_password(self, password):
        crypto = TestCryptoUtilOperations()
        private_key = os.path.join(self.tmp_dir, "TransportPrivate.pem")
        public_key = os.path.join(self.tmp_dir, "TransportPublic.pem")
        certificate = os.path.join(self.tmp_dir, "Transport.cert")
        cache_file = os.path.join(self.tmp_dir, "encrypted.enc")
        self.prv_key, self.pub_key, self.cert = crypto.create_keys(private_key, public_key, certificate)
        return crypto.encrypt_string(password, self.cert, cache_file)

