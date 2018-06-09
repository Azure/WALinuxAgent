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

    # add_user tests
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
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
        self.assertEqual(actual_user[4], "JIT Account")

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_bad_creation_data(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = ""
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(0, os_util.all_users.keys().__len__())

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="")
    def test_add_user_bad_password_data(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = ""
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(0, os_util.all_users.keys().__len__())

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_already_existing(self, _):
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
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
        self.assertEqual(1, os_util.all_users.keys().__len__())
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
        # add the new duplicate user, ensure it's not created and does not overwrite the existing user.
        # this does not test the user add function as that's mocked, it tests processing skips the remaining
        # calls after the initial failure
        new_user_expiration = datetime.utcnow() + timedelta(days=5)
        rah.add_user(tstuser, pwd, new_user_expiration)
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users after dup user attempted".format(tstuser))
        self.assertEqual(1, os_util.all_users.keys().__len__())
        actual_user = os_util.all_users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))

    # delete_user tests
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
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
        rah.delete_user(tstuser)
        self.assertFalse(tstuser in os_util.all_users)

    def test_handle_failed_create_with_bad_data(self):
        mockOSUtil = MockOSUtil()
        testusr = "foobar"
        mockOSUtil.all_users[testusr] = (testusr, None, None, None, None, None, None, None)
        rah = RemoteAccessHandler()
        rah.os_util = mockOSUtil
        rah.handle_failed_create("", "test message")
        self.assertEqual(1, mockOSUtil.all_users.keys().__len__())
        self.assertTrue(testusr in mockOSUtil.all_users, "Expected user {0} missing".format(testusr))

    def test_delete_user_does_not_exist(self):
        mockOSUtil = MockOSUtil()
        testusr = "foobar"
        mockOSUtil.all_users[testusr] = (testusr, None, None, None, None, None, None, None)
        rah = RemoteAccessHandler()
        rah.os_util = mockOSUtil
        rah.handle_failed_create("Carl", "test message")
        self.assertEqual(1, mockOSUtil.all_users.keys().__len__())
        self.assertTrue(testusr in mockOSUtil.all_users, "Expected user {0} missing".format(testusr))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_new_user(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        tstuser = remote_access.user_list.users[0].name
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser, "{0} missing from users".format(tstuser))
        actual_user = os_util.all_users[tstuser]
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

    def test_handle_remote_access_no_users(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_no_accounts.xml')
        remote_access = RemoteAccess(data_str)
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(0, os_util.all_users.keys().__len__())

    def test_handle_remote_access_validate_jit_user_valid(self):
        rah = RemoteAccessHandler()
        result = rah.validate_jit_user("JIT Account")
        self.assertTrue(result, "JIT account incorrectly identified.")

    def test_handle_remote_access_validate_jit_user_invalid(self):
        rah = RemoteAccessHandler()
        result = rah.validate_jit_user("John Doe")
        self.assertFalse(result, "JIT account incorrectly identified.")
        
    def test_handle_remote_access_validate_jit_user_None(self):
        rah = RemoteAccessHandler()
        result = rah.validate_jit_user(None)
        self.assertFalse(result, "JIT account incorrectly identified.")

    def test_handle_remote_access_validate_jit_user_blank(self):
        rah = RemoteAccessHandler()
        result = rah.validate_jit_user("")
        self.assertFalse(result, "JIT account incorrectly identified.")

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_two_accounts.xml')
        remote_access = RemoteAccess(data_str)
        tstuser = remote_access.user_list.users[0].name
        tstuser2 = remote_access.user_list.users[1].name
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration_date2 = datetime.utcnow() + timedelta(days=5)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        expiration2 = (expiration_date2).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        remote_access.user_list.users[1].expiration = expiration2
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser, "{0} missing from users".format(tstuser))
        self.assertTrue(tstuser2, "{0} missing from users".format(tstuser2))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    # max fabric supports in the Goal State
    def test_handle_remote_access_ten_users(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_10_accounts.xml')
        remote_access = RemoteAccess(data_str)
        count = 0
        for user in remote_access.user_list.users:
            count += 1
            user.name = "tstuser{0}".format(count)
            expiration_date = datetime.utcnow() + timedelta(days=count)
            user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(10, os_util.all_users.keys().__len__())

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_user_removed(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_10_accounts.xml')
        remote_access = RemoteAccess(data_str)
        count = 0
        for user in remote_access.user_list.users:
            count += 1
            user.name = "tstuser{0}".format(count)
            expiration_date = datetime.utcnow() + timedelta(days=count)
            user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(10, os_util.all_users.keys().__len__())
        del rah.remote_access.user_list.users[:]
        self.assertEqual(10, os_util.all_users.keys().__len__())

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_bad_data_and_good_data(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_10_accounts.xml')
        remote_access = RemoteAccess(data_str)
        count = 0
        for user in remote_access.user_list.users:
            count += 1
            user.name = "tstuser{0}".format(count)
            if count is 2:
                user.name = ""
            expiration_date = datetime.utcnow() + timedelta(days=count)
            user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertEqual(9, os_util.all_users.keys().__len__())

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_deleted_user_readded(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        tstuser = remote_access.user_list.users[0].name
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = (expiration_date).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
        os_util.all_users.clear()
        self.assertTrue(tstuser not in os_util.all_users)
        rah.handle_remote_access()
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
    return_value="]aPPEv}uNg1FPnl?")
    @patch('azurelinuxagent.common.osutil.get_osutil',
    return_value=MockOSUtil())
    @patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol',
    return_value=WireProtocol("12.34.56.78"))
    @patch('azurelinuxagent.common.protocol.wire.WireProtocol.get_incarnation',
    return_value="1")
    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_remote_access',
    return_value="asdf")
    def test_remote_access_handler_run_bad_data(self, _1, _2, _3, _4, _5):
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
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
        rah.run()
        self.assertTrue(tstuser in os_util.all_users, "{0} missing from users".format(tstuser))
