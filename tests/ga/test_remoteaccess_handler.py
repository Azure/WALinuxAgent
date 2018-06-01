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
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_add_user(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
        self.assertEqual(actual_user[4], "JIT Account")

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")    
    def test_delete_user(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users)
        rah.delete_user(tstuser)
        self.assertFalse(tstuser in os_util.all_users)

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_new_user(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()  
        tstpassword = "]aPPEv}uNg1FPnl?"    
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(remote_access.user_list.users[0].name in os_util.all_users)
        actual_user = os_util.all_users[remote_access.user_list.users[0].name]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
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
        rah.add_user(tstuser, pwd, expiration)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertFalse(tstuser in os_util.all_users)  
