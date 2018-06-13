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

from datetime import timedelta
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler
from tests.common.osutil.mock_osutil import MockOSUtil
from tests.tools import *


info_messages = []
error_messages = []


def get_user_dictionary(users):
    user_dictionary = {}
    for user in users:
        user_dictionary[user[0]] = user
    return user_dictionary


def log_info(msg_format, *args):
    info_messages.append(msg_format.format(args))


def log_error(msg_format, *args):
    error_messages.append(msg_format.format(args))


class TestRemoteAccessHandler(AgentTestCase):

    def setUp(self):
        super(TestRemoteAccessHandler, self).setUp()
        del info_messages[:]
        del error_messages[:]

    # add_user tests
    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_add_user(self, _1, _2, _3):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        actual_user = users[tstuser]
        expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")
        self.assertEqual(actual_user[7], expected_expiration)
        self.assertEqual(actual_user[4], "JIT_Account")
        self.assertEqual(0, len(error_messages))
        self.assertEqual(1, len(info_messages))
        self.assertEqual(info_messages[0], "User '{0}' added successfully with expiration in {1}"
                         .format(tstuser, expected_expiration))

    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_bad_creation_data(self, _1, _2, _3):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = ""
        expiration_date = datetime.utcnow() + timedelta(days=1)
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        self.assertEqual(0, len(rah.os_util.get_users()))
        self.assertEqual(1, len(error_messages))
        self.assertEqual(0, len(info_messages))
        error = "Error adding user {0}. test exception for bad username".format(tstuser)
        self.assertEqual(error, error_messages[0])

    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="")
    def test_add_user_bad_password_data(self, _1, _2, _3):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = ""
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        self.assertEqual(0, len(rah.os_util.get_users()))
        self.assertEqual(1, len(error_messages))
        self.assertEqual(1, len(info_messages))
        error = "Error creating user {0}. test exception for bad password".format(tstuser)
        self.assertEqual(error, error_messages[0])
        self.assertEqual("User deleted {0}".format(tstuser), info_messages[0])

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
           return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_already_existing(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        self.assertEqual(1, len(users.keys()))
        actual_user = users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
        # add the new duplicate user, ensure it's not created and does not overwrite the existing user.
        # this does not test the user add function as that's mocked, it tests processing skips the remaining
        # calls after the initial failure
        new_user_expiration = datetime.utcnow() + timedelta(days=5)
        rah.add_user(tstuser, pwd, new_user_expiration)
        # refresh users
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users after dup user attempted".format(tstuser))
        self.assertEqual(1, len(users.keys()))
        actual_user = users[tstuser]
        self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))

    # delete_user tests
    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_delete_user(self, _1, _2, _3):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstpassword = "]aPPEv}uNg1FPnl?"
        tstuser = "foobar"
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        rah.delete_user(tstuser)
        # refresh users
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertFalse(tstuser in users)
        self.assertEqual(0, len(error_messages))
        self.assertEqual(2, len(info_messages))
        self.assertEqual("User '{0}' added successfully with expiration in {1}".format(tstuser, expected_expiration),
                         info_messages[0])
        self.assertEqual("User deleted {0}".format(tstuser), info_messages[1])

    def test_handle_failed_create_with_bad_data(self):
        mock_os_util = MockOSUtil()
        testusr = "foobar"
        mock_os_util.all_users[testusr] = (testusr, None, None, None, None, None, None, None)
        rah = RemoteAccessHandler()
        rah.os_util = mock_os_util
        rah.handle_failed_create("", "test message")
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(1, len(users.keys()))
        self.assertTrue(testusr in users, "Expected user {0} missing".format(testusr))

    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    def test_delete_user_does_not_exist(self, _1, _2):
        mock_os_util = MockOSUtil()
        testusr = "foobar"
        mock_os_util.all_users[testusr] = (testusr, None, None, None, None, None, None, None)
        rah = RemoteAccessHandler()
        rah.os_util = mock_os_util
        testuser = "Carl"
        test_message = "test message"
        rah.handle_failed_create(testuser, test_message)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(1, len(users.keys()))
        self.assertTrue(testusr in users, "Expected user {0} missing".format(testusr))
        self.assertEqual(2, len(error_messages))
        self.assertEqual(0, len(info_messages))
        self.assertEqual("Error creating user {0}. {1}".format(testuser, test_message), error_messages[0])
        msg = "Failed to clean up after account creation for {0}. test exception, user does not exist to delete"\
            .format(testuser)
        self.assertEqual(msg, error_messages[1])

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
           return_value="]aPPEv}uNg1FPnl?")
    def test_handle_new_user(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        tstuser = remote_access.user_list.users[0].name
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        actual_user = users[tstuser]
        expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")
        self.assertEqual(actual_user[7], expected_expiration)
        self.assertEqual(actual_user[4], "JIT_Account")

    def test_do_not_add_expired_user(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()      
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        expiration = (datetime.utcnow() - timedelta(days=2)).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertFalse("testAccount" in users)

    @patch('azurelinuxagent.common.logger.Logger.info', side_effect=log_info)
    @patch('azurelinuxagent.common.logger.Logger.error', side_effect=log_error)
    def test_error_add_user(self, _1, _2):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        tstuser = "foobar"
        expiration = datetime.utcnow() + timedelta(days=1)
        pwd = "bad password"
        rah.add_user(tstuser, pwd, expiration)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(0, len(users))
        self.assertEqual(1, len(error_messages))
        self.assertEqual(1, len(info_messages))
        error = "Error creating user {0}. [CryptError] Error decoding secret\nInner error: Incorrect padding".\
            format(tstuser)
        self.assertEqual(error, error_messages[0])
        self.assertEqual("User deleted {0}".format(tstuser), info_messages[0])

    def test_handle_remote_access_no_users(self):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_no_accounts.xml')
        remote_access = RemoteAccess(data_str)
        rah.remote_access = remote_access
        rah.handle_remote_access()
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(0, len(users.keys()))

    def test_handle_remote_access_validate_jit_user_valid(self):
        rah = RemoteAccessHandler()
        comment = "JIT_Account"
        result = rah.validate_jit_user(comment)
        self.assertTrue(result, "Did not identify '{0}' as a JIT_Account".format(comment))

    def test_handle_remote_access_validate_jit_user_invalid(self):
        rah = RemoteAccessHandler()
        test_users = ["John Doe", None, "", " "]
        failed_results = ""
        for user in test_users:
            if rah.validate_jit_user(user):
                failed_results += "incorrectly identified '{0} as a JIT_Account'.  ".format(user)
        if len(failed_results) > 0:
            self.fail(failed_results)

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
           return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_two_accounts.xml')
        remote_access = RemoteAccess(data_str)
        testusers = []
        count = 0
        while count < 2:
            user = remote_access.user_list.users[count].name
            expiration_date = datetime.utcnow() + timedelta(days=count + 1)
            expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            remote_access.user_list.users[count].expiration = expiration
            testusers.append(user)
            count += 1
        rah.remote_access = remote_access
        rah.handle_remote_access()
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(testusers[0] in users, "{0} missing from users".format(testusers[0]))
        self.assertTrue(testusers[1] in users, "{0} missing from users".format(testusers[1]))

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
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(10, len(users.keys()))

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
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(10, len(users.keys()))
        del rah.remote_access.user_list.users[:]
        self.assertEqual(10, len(users.keys()))

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
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertEqual(9, len(users.keys()))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret',
           return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_deleted_user_readded(self, _):
        rah = RemoteAccessHandler()
        rah.os_util = MockOSUtil()
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        tstuser = remote_access.user_list.users[0].name
        expiration_date = datetime.utcnow() + timedelta(days=1)
        expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
        remote_access.user_list.users[0].expiration = expiration
        rah.remote_access = remote_access
        rah.handle_remote_access()
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        os_util = rah.os_util
        os_util.__class__ = MockOSUtil
        os_util.all_users.clear()
        # refresh users
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser not in users)
        rah.handle_remote_access()
        # refresh users
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))

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
        pwd = tstpassword
        rah.add_user(tstuser, pwd, expiration_date)
        users = get_user_dictionary(rah.os_util.get_users())
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
        rah.run()
        self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
