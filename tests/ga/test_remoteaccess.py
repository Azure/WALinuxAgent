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

from tests.tools import *
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.osutil import get_osutil

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

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state',
    return_value=GoalState(load_data('wire/goal_state.xml')))
    def test_update_remote_access_conf_no_remote_access(self, _):
        protocol = WireProtocol('12.34.56.78')
        goal_state = protocol.client.get_goal_state()
        protocol.client.update_remote_access_conf(goal_state)

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

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state',
    return_value=GoalState(load_data('wire/goal_state_remote_access.xml')))
    @patch('azurelinuxagent.common.protocol.wire.WireClient.fetch_config',
    return_value=load_data('wire/remote_access_single_account.xml'))
    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_header_for_cert')
    def test_update_remote_access_conf_remote_access(self, _1, _2, _3):
        protocol = WireProtocol('12.34.56.78')
        goal_state = protocol.client.get_goal_state()
        protocol.client.update_remote_access_conf(goal_state)
        self.assertNotEquals(None, protocol.client.remote_access)
        self.assertEquals(1, len(protocol.client.remote_access.user_list.users))
        self.assertEquals('testAccount', protocol.client.remote_access.user_list.users[0].name)
        self.assertEquals('encryptedPasswordString', protocol.client.remote_access.user_list.users[0].encrypted_password)

    def test_parse_bad_remote_access_data(self):
        data = "foobar"
        self.assertRaises(xml.parsers.expat.ExpatError, RemoteAccess, data)