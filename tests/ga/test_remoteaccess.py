# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

from tests.tools import *
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.osutil import get_osutil

class TestRemoteAccess(AgentTestCase):
    def test_parse_remote_access(self):
        data_str = load_data('wire/remote_access_single_account.xml')
        remoteAccess = RemoteAccess(data_str)
        self.assertNotEquals(None, remoteAccess)
        self.assertEquals(1, remoteAccess.Incarnation)
        self.assertEquals(1, len(remoteAccess.Users))
        self.assertEquals("testAccount", remoteAccess.Users[0].Name)
        self.assertEquals("encryptedPasswordString", remoteAccess.Users[0].EncryptedPassword)
        self.assertEquals("2019-01-01", remoteAccess.Users[0].Expiration)
        #self.assertEquals(2, len(remoteAccess.Users[0].Groups))
        #self.assertNotEquals(-1, remoteAccess.Users[0].Groups.index("Administrators"))

        osUtil = get_osutil()
        osUtil.useradd('testUser1')

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state',
    return_value=GoalState(load_data('wire/goal_state.xml')))
    def test_update_remote_access_conf_no_remote_access(self, _):
        protocol = WireProtocol('12.34.56.78')
        goal_state = protocol.client.get_goal_state()
        protocol.client.update_remote_access_conf(goal_state)
        self.assertNotEquals(None, protocol.client.remote_access)
        self.assertEquals(0, len(protocol.client.remote_access.Users))

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
        self.assertEquals(1, len(protocol.client.remote_access.Users))
        self.assertEquals('testAccount', protocol.client.remote_access.Users[0].Name)
        self.assertEquals('encryptedPasswordString', protocol.client.remote_access.Users[0].EncryptedPassword)
        #self.assertEquals(2, len(protocol.client.remote_access.Users[0].Groups))
        #self.assertEquals('Administrators', protocol.client.remote_access.Users[0].Groups[0])
        #self.assertEquals('RemoteDesktopUsers', protocol.client.remote_access.Users[0].Groups[1])




