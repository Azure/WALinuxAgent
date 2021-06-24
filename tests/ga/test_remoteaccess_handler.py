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
from datetime import timedelta, datetime

from mock import Mock, MagicMock
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.protocol.goal_state import RemoteAccess
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler
from tests.tools import AgentTestCase, load_data, patch, clear_singleton_instances
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol.mockwiredata import DATA_FILE, DATA_FILE_REMOTE_ACCESS


class MockOSUtil(DefaultOSUtil):
    def __init__(self):  # pylint: disable=super-init-not-called
        self.all_users = {}
        self.sudo_users = set()
        self.jit_enabled = True

    def useradd(self, username, expiration=None, comment=None):
        if username == "":
            raise Exception("test exception for bad username")
        if username in self.all_users:
            raise Exception("test exception, user already exists")
        self.all_users[username] = (username, None, None, None, comment, None, None, expiration)

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        if not remove:
            self.sudo_users.add(username)
        else:
            self.sudo_users.remove(username)

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if password == "":
            raise Exception("test exception for bad password")
        user = self.all_users[username]
        self.all_users[username] = (user[0], password, user[2], user[3], user[4], user[5], user[6], user[7])

    def del_account(self, username):
        if username == "":
            raise Exception("test exception, bad data")
        if username not in self.all_users:
            raise Exception("test exception, user does not exist to delete")
        self.all_users.pop(username)

    def get_users(self):
        return self.all_users.values()


def get_user_dictionary(users):
    user_dictionary = {}
    for user in users:
        user_dictionary[user[0]] = user
    return user_dictionary


def mock_add_event(name, op, is_success, version, message):
    TestRemoteAccessHandler.eventing_data = (name, op, is_success, version, message)


class TestRemoteAccessHandler(AgentTestCase):
    eventing_data = [()]

    def setUp(self):
        super(TestRemoteAccessHandler, self).setUp()
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)
        for data in TestRemoteAccessHandler.eventing_data:
            del data

    # add_user tests
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_add_user(self, *_):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = "]aPPEv}uNg1FPnl?"
            tstuser = "foobar"
            expiration_date = datetime.utcnow() + timedelta(days=1)
            pwd = tstpassword
            rah._add_user(tstuser, pwd, expiration_date)  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            actual_user = users[tstuser]
            expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")
            self.assertEqual(actual_user[7], expected_expiration)
            self.assertEqual(actual_user[4], "JIT_Account")

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_bad_creation_data(self, *_):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = "]aPPEv}uNg1FPnl?"
            tstuser = ""
            expiration = datetime.utcnow() + timedelta(days=1)
            pwd = tstpassword
            error = "test exception for bad username"
            self.assertRaisesRegex(Exception, error, rah._add_user, tstuser, pwd, expiration)  # pylint: disable=protected-access
            self.assertEqual(0, len(rah._os_util.get_users()))  # pylint: disable=protected-access

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="")
    def test_add_user_bad_password_data(self, *_):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = ""
            tstuser = "foobar"
            expiration = datetime.utcnow() + timedelta(days=1)
            pwd = tstpassword
            error = "test exception for bad password"
            self.assertRaisesRegex(Exception, error, rah._add_user, tstuser, pwd, expiration)  # pylint: disable=protected-access
            self.assertEqual(0, len(rah._os_util.get_users()))  # pylint: disable=protected-access

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_add_user_already_existing(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = "]aPPEv}uNg1FPnl?"
            tstuser = "foobar"
            expiration_date = datetime.utcnow() + timedelta(days=1)
            pwd = tstpassword
            rah._add_user(tstuser, pwd, expiration_date)  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            self.assertEqual(1, len(users.keys()))
            actual_user = users[tstuser]
            self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))
            # add the new duplicate user, ensure it's not created and does not overwrite the existing user.
            # this does not test the user add function as that's mocked, it tests processing skips the remaining
            # calls after the initial failure
            new_user_expiration = datetime.utcnow() + timedelta(days=5)
            self.assertRaises(Exception, rah._add_user, tstuser, pwd, new_user_expiration)  # pylint: disable=protected-access
            # refresh users
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users after dup user attempted".format(tstuser))
            self.assertEqual(1, len(users.keys()))
            actual_user = users[tstuser]
            self.assertEqual(actual_user[7], (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d"))

    # delete_user tests
    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_delete_user(self, *_):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = "]aPPEv}uNg1FPnl?"
            tstuser = "foobar"
            expiration_date = datetime.utcnow() + timedelta(days=1)
            expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")  # pylint: disable=unused-variable
            pwd = tstpassword
            rah._add_user(tstuser, pwd, expiration_date)  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            rah._remove_user(tstuser)  # pylint: disable=protected-access
            # refresh users
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertFalse(tstuser in users)

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_new_user(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_single_account.xml')
            remote_access = RemoteAccess(data_str)
            tstuser = remote_access.user_list.users[0].name
            expiration_date = datetime.utcnow() + timedelta(days=1)
            expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            remote_access.user_list.users[0].expiration = expiration
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            actual_user = users[tstuser]
            expected_expiration = (expiration_date + timedelta(days=1)).strftime("%Y-%m-%d")
            self.assertEqual(actual_user[7], expected_expiration)
            self.assertEqual(actual_user[4], "JIT_Account")

    def test_do_not_add_expired_user(self):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_single_account.xml')
            remote_access = RemoteAccess(data_str)
            expiration = (datetime.utcnow() - timedelta(days=2)).strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            remote_access.user_list.users[0].expiration = expiration
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertFalse("testAccount" in users)

    def test_error_add_user(self):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstuser = "foobar"
            expiration = datetime.utcnow() + timedelta(days=1)
            pwd = "bad password"
            error = r"\[CryptError\] Error decoding secret\nInner error: Incorrect padding"
            self.assertRaisesRegex(Exception, error, rah._add_user, tstuser, pwd, expiration)  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertEqual(0, len(users))

    def test_handle_remote_access_no_users(self):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_no_accounts.xml')
            remote_access = RemoteAccess(data_str)
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertEqual(0, len(users.keys()))

    def test_handle_remote_access_validate_jit_user_valid(self):
        rah = RemoteAccessHandler(Mock())
        comment = "JIT_Account"
        result = rah._is_jit_user(comment)  # pylint: disable=protected-access
        self.assertTrue(result, "Did not identify '{0}' as a JIT_Account".format(comment))

    def test_handle_remote_access_validate_jit_user_invalid(self):
        rah = RemoteAccessHandler(Mock())
        test_users = ["John Doe", None, "", " "]
        failed_results = ""
        for user in test_users:
            if rah._is_jit_user(user):  # pylint: disable=protected-access
                failed_results += "incorrectly identified '{0} as a JIT_Account'.  ".format(user)
        if len(failed_results) > 0:
            self.fail(failed_results)

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
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
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(testusers[0] in users, "{0} missing from users".format(testusers[0]))
            self.assertTrue(testusers[1] in users, "{0} missing from users".format(testusers[1]))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    # max fabric supports in the Goal State
    def test_handle_remote_access_ten_users(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertEqual(10, len(users.keys()))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_user_removed(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertEqual(10, len(users.keys()))
            del rah._remote_access.user_list.users[:]  # pylint: disable=protected-access
            self.assertEqual(10, len(users.keys()))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_bad_data_and_good_data(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                if count == 2:
                    user.name = ""
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertEqual(9, len(users.keys()))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_deleted_user_readded(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_single_account.xml')
            remote_access = RemoteAccess(data_str)
            tstuser = remote_access.user_list.users[0].name
            expiration_date = datetime.utcnow() + timedelta(days=1)
            expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            remote_access.user_list.users[0].expiration = expiration
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            os_util = rah._os_util  # pylint: disable=protected-access
            os_util.__class__ = MockOSUtil
            os_util.all_users.clear()  # pylint: disable=no-member
            # refresh users
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser not in users)
            rah._handle_remote_access()  # pylint: disable=protected-access
            # refresh users
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    @patch('azurelinuxagent.common.osutil.get_osutil', return_value=MockOSUtil())
    @patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=WireProtocol("12.34.56.78"))
    @patch('azurelinuxagent.common.protocol.wire.WireProtocol.get_incarnation', return_value="1")
    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_remote_access', return_value="asdf")
    def test_remote_access_handler_run_bad_data(self, _1, _2, _3, _4, _5):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            tstpassword = "]aPPEv}uNg1FPnl?"
            tstuser = "foobar"
            expiration_date = datetime.utcnow() + timedelta(days=1)
            pwd = tstpassword
            rah._add_user(tstuser, pwd, expiration_date)  # pylint: disable=protected-access
            users = get_user_dictionary(rah._os_util.get_users())  # pylint: disable=protected-access
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))
            rah.run()
            self.assertTrue(tstuser in users, "{0} missing from users".format(tstuser))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users_one_removed(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(10, len(users))
            # now remove the user from RemoteAccess
            deleted_user = rah._remote_access.user_list.users[3]  # pylint: disable=protected-access
            del rah._remote_access.user_list.users[3]  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertTrue(deleted_user not in users, "{0} still in users".format(deleted_user))
            self.assertEqual(9, len(users))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users_null_remote_access(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(10, len(users))
            # now remove the user from RemoteAccess
            rah._remote_access = None  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(0, len(users))

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_multiple_users_error_with_null_remote_access(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(10, len(users))
            # now remove the user from RemoteAccess
            rah._remote_access = None  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(0, len(users))

    def test_remove_user_error(self):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            error = "test exception, bad data"
            self.assertRaisesRegex(Exception, error, rah._remove_user, "")  # pylint: disable=protected-access

    def test_remove_user_not_exists(self):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            user = "bob"
            error = "test exception, user does not exist to delete"
            self.assertRaisesRegex(Exception, error, rah._remove_user, user)  # pylint: disable=protected-access

    @patch('azurelinuxagent.common.utils.cryptutil.CryptUtil.decrypt_secret', return_value="]aPPEv}uNg1FPnl?")
    def test_handle_remote_access_remove_and_add(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            rah = RemoteAccessHandler(Mock())
            data_str = load_data('wire/remote_access_10_accounts.xml')
            remote_access = RemoteAccess(data_str)
            count = 0
            for user in remote_access.user_list.users:
                count += 1
                user.name = "tstuser{0}".format(count)
                expiration_date = datetime.utcnow() + timedelta(days=count)
                user.expiration = expiration_date.strftime("%a, %d %b %Y %H:%M:%S ") + "UTC"
            rah._remote_access = remote_access  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertEqual(10, len(users))
            # now remove the user from RemoteAccess
            new_user = "tstuser11"
            deleted_user = rah._remote_access.user_list.users[3]  # pylint: disable=protected-access
            rah._remote_access.user_list.users[3].name = new_user  # pylint: disable=protected-access
            rah._handle_remote_access()  # pylint: disable=protected-access
            users = rah._os_util.get_users()  # pylint: disable=protected-access
            self.assertTrue(deleted_user not in users, "{0} still in users".format(deleted_user))
            self.assertTrue(new_user in [u[0] for u in users], "user {0} not in users".format(new_user))
            self.assertEqual(10, len(users))

    @patch('azurelinuxagent.ga.remoteaccess.add_event', side_effect=mock_add_event)
    def test_remote_access_handler_run_error(self, _):
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=MockOSUtil()):
            mock_protocol = WireProtocol("foo.bar")
            mock_protocol.get_incarnation = MagicMock(side_effect=Exception("foobar!"))

            rah = RemoteAccessHandler(mock_protocol)
            rah.run()
            print(TestRemoteAccessHandler.eventing_data)
            check_message = "foobar!"
            self.assertTrue(check_message in TestRemoteAccessHandler.eventing_data[4],
                            "expected message {0} not found in {1}"
                            .format(check_message, TestRemoteAccessHandler.eventing_data[4]))
            self.assertEqual(False, TestRemoteAccessHandler.eventing_data[2], "is_success is true")

    def test_remote_access_handler_should_retrieve_users_when_it_is_invoked_the_first_time(self):
        mock_os_util = MagicMock()
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=mock_os_util):
            with mock_wire_protocol(DATA_FILE) as mock_protocol:
                rah = RemoteAccessHandler(mock_protocol)
                rah.run()

                self.assertTrue(len(mock_os_util.get_users.call_args_list) == 1, "The first invocation of remote access should have retrieved the current users")

    def test_remote_access_handler_should_retrieve_users_when_goal_state_contains_jit_users(self):
        mock_os_util = MagicMock()
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=mock_os_util):
            with mock_wire_protocol(DATA_FILE_REMOTE_ACCESS) as mock_protocol:
                rah = RemoteAccessHandler(mock_protocol)
                rah.run()

                self.assertTrue(len(mock_os_util.get_users.call_args_list) > 0, "A goal state with jit users did not retrieve the current users")

    def test_remote_access_handler_should_not_retrieve_users_when_goal_state_does_not_contain_jit_users(self):
        mock_os_util = MagicMock()
        with patch("azurelinuxagent.ga.remoteaccess.get_osutil", return_value=mock_os_util):
            with mock_wire_protocol(DATA_FILE) as mock_protocol:
                rah = RemoteAccessHandler(mock_protocol)
                rah.run()  # this will trigger one call to retrieve the users

                mock_protocol.mock_wire_data.set_incarnation(123)  # mock a new goal state; the data file does not include any jit users
                rah.run()
                self.assertTrue(len(mock_os_util.get_users.call_args_list) == 1, "A goal state without jit users retrieved the current users")

