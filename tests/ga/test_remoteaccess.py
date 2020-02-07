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

from azurelinuxagent.common.goal_state import GoalState, RemoteAccess
from tests.tools import AgentTestCase, load_data, patch, Mock
from tests.protocol import mockwiredata, mock_wire_protocol


class TestRemoteAccess(AgentTestCase):
    def test_parse_remote_access(self):
        data_str = load_data('wire/remote_access_single_account.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEquals(None, remote_access)
        self.assertEquals("1", remote_access.incarnation)
        self.assertEquals(1, len(remote_access.user_list.users), "User count does not match.")
        self.assertEquals("testAccount", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEquals("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEquals("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")

    def test_goal_state_with_no_remote_access(self):
        mock_wire_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        with mock_wire_protocol.create(mock_wire_data) as protocol:
            goal_state = GoalState.fetch_full_goal_state(protocol.client)
            self.assertIsNone(goal_state.remote_access)

    def test_parse_two_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_two_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEquals(None, remote_access)
        self.assertEquals("1", remote_access.incarnation)
        self.assertEquals(2, len(remote_access.user_list.users), "User count does not match.")
        self.assertEquals("testAccount1", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEquals("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEquals("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")
        self.assertEquals("testAccount2", remote_access.user_list.users[1].name, "Account name does not match")
        self.assertEquals("encryptedPasswordString", remote_access.user_list.users[1].encrypted_password, "Encrypted password does not match.")
        self.assertEquals("2019-01-01", remote_access.user_list.users[1].expiration, "Expiration does not match.")

    def test_parse_ten_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_10_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEquals(None, remote_access)
        self.assertEquals(10, len(remote_access.user_list.users), "User count does not match.")

    def test_parse_duplicate_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_duplicate_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEquals(None, remote_access)
        self.assertEquals(2, len(remote_access.user_list.users), "User count does not match.")
        self.assertEquals("testAccount", remote_access.user_list.users[0].name, "Account name does not match")
        self.assertEquals("encryptedPasswordString", remote_access.user_list.users[0].encrypted_password, "Encrypted password does not match.")
        self.assertEquals("2019-01-01", remote_access.user_list.users[0].expiration, "Expiration does not match.")
        self.assertEquals("testAccount", remote_access.user_list.users[1].name, "Account name does not match")
        self.assertEquals("encryptedPasswordString", remote_access.user_list.users[1].encrypted_password, "Encrypted password does not match.")
        self.assertEquals("2019-01-01", remote_access.user_list.users[1].expiration, "Expiration does not match.")

    def test_parse_zero_remote_access_accounts(self):
        data_str = load_data('wire/remote_access_no_accounts.xml')
        remote_access = RemoteAccess(data_str)
        self.assertNotEquals(None, remote_access)
        self.assertEquals(0, len(remote_access.user_list.users), "User count does not match.")

    def test_update_remote_access_conf_remote_access(self):
        mock_wire_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_REMOTE_ACCESS)
        with mock_wire_protocol.create(mock_wire_data) as protocol:
            goal_state = GoalState.fetch_full_goal_state(protocol.client)
            self.assertIsNotNone(goal_state.remote_access)
            self.assertEquals(1, len(protocol.client.get_remote_access().user_list.users))
            self.assertEquals('testAccount', protocol.client.get_remote_access().user_list.users[0].name)
            self.assertEquals('encryptedPasswordString', protocol.client.get_remote_access().user_list.users[0].encrypted_password)

    def test_parse_bad_remote_access_data(self):
        data = "foobar"
        self.assertRaises(xml.parsers.expat.ExpatError, RemoteAccess, data)