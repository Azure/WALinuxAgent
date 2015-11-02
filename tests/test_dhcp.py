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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import tests.env as env
from tests.tools import *
import uuid
import unittest
import os
import json
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.protocol.dhcp as dhcp

SampleDhcpResponse = None
with open(os.path.join(env.test_root, "dhcp"), 'rb') as F:
     SampleDhcpResponse = F.read()
        
mock_socket_send = MockFunc('socket_send', SampleDhcpResponse)
mock_gen_trans_id = MockFunc('gen_trans_id', "\xC6\xAA\xD1\x5D")
mock_get_mac_addr = MockFunc('get_mac_addr', "\x00\x15\x5D\x38\xAA\x38")
mock_send_dhcp_failed = MockFunc(retval=None)

class TestdhcpHandler(unittest.TestCase):
 
    def test_build_dhcp_req(self):
        req = dhcp.build_dhcp_request(mock_get_mac_addr())
        self.assertNotEquals(None, req)

    @mock(dhcp, "gen_trans_id", mock_gen_trans_id)
    @mock(dhcp, "socket_send", mock_socket_send)
    def test_send_dhcp_req(self):
        req = dhcp.build_dhcp_request(mock_get_mac_addr())
        resp = dhcp.send_dhcp_request(req)
        self.assertNotEquals(None, resp)

    @mock(dhcp, "send_dhcp_request", mock_send_dhcp_failed)
    def test_send_dhcp_failed(self):
        dhcp_resp = dhcp.DHCPCLIENT.get_dhcp_resp()

    @mock(dhcp, "socket_send", mock_socket_send)
    @mock(dhcp, "gen_trans_id", mock_gen_trans_id)
    @mock(dhcp.OSUTIL, "get_mac_addr", mock_get_mac_addr)
    @mock(dhcp.fileutil, "write_file", MockFunc())
    def test_handle_dhcp(self):
        dhcp_resp = dhcp.DHCPCLIENT.get_dhcp_resp()
        self.assertEquals("10.62.144.1", dhcp_resp.gateway)
        self.assertEquals("10.62.144.140", dhcp_resp.endpoint)

if __name__ == '__main__':
    unittest.main()
