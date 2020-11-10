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
import xml

from azurelinuxagent.common.protocol.goal_state import GoalState, RemoteAccess  # pylint: disable=unused-import
from tests.tools import AgentTestCase, load_data, patch, Mock  # pylint: disable=unused-import
from tests.protocol import mockwiredata
from tests.protocol.mocks import mock_wire_protocol


class TestRemoteAccess(AgentTestCase):
    def test_parse_remote_access(self):
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEqual(None, remote_access)
        self.assertEqual("1", remote_access.incarnation)
        self.assertEqual(1, len(remote_access.user_list.users), "User count does not match.")
        self.assertEqual("testAccount", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEqual("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEqual("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")

    def test_goal_state_with_no_remote_access(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            self.assertIsNone(protocol.client.get_remote_access())

    def test_parse_two_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_two_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEqual(None, remote_access)
        self.assertEqual("1", remote_access.incarnation)
        self.assertEqual(2, len(remote_access.user_list.users), "User count does not match.")
        self.assertEqual("testAccount1", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEqual("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEqual("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")
        self.assertEqual("testAccount2", remote_access.user_list.users[1].name, "Account name does not match")
        self.assertEqual("encryptedPasswordString", remote_access.user_list.users[1].encrypted_password, "Encrypted password does not match.")
        self.assertEqual("2019-01-01", remote_access.user_list.users[1].expiration, "Expiration does not match.")

    def test_parse_ten_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_10_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEqual(None, remote_access)
        self.assertEqual(10, len(remote_access.user_list.users), "User count does not match.")

    def test_parse_duplicate_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_duplicate_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEqual(None, remote_access)
        self.assertEqual(2, len(remote_access.user_list.users), "User count does not match.")
        self.assertEqual("testAccount", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEqual("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEqual("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")
        self.assertEqual("testAccount", remote_access.user_list.users[1].name, "Account name does not match")
        self.assertEqual("encryptedPasswordString", remote_access.user_list.users[1].encrypted_password, "Encrypted password does not match.")
        self.assertEqual("2019-01-01", remote_access.user_list.users[1].expiration, "Expiration does not match.")

    def test_parse_zero_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_no_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEqual(None, remote_access)
        self.assertEqual(0, len(remote_access.user_list.users), "User count does not match.")

    def test_update_remote_access_conf_remote_access(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_REMOTE_ACCESS) as protocol:
            self.assertIsNotNone(protocol.client.get_remote_access())
            self.assertEqual(1, len(protocol.client.get_remote_access().user_list.users))
            self.assertEqual('testAccount', protocol.client.get_remote_access().user_list.users[0].name)
            self.assertEqual('encryptedPasswordString', protocol.client.get_remote_access().user_list.users[0].encrypted_password)

    def test_parse_bad_remote_access_data(self):
        data = "foobar"
        self.assertRaises(xml.parsers.expat.ExpatError, RemoteAccess, data)