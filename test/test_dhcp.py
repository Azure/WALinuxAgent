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

import env
import test.tools as tools
from tools import *
import uuid
import unittest
import os
import json
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.dhcphandler as dhcphandler

SampleDhcpResponse = None
with open(os.path.join(env.test_root, "dhcp")) as F:
     SampleDhcpResponse = F.read()
        
MockSocketSend = MockFunc('SocketSend', SampleDhcpResponse)
MockGenTransactionId = MockFunc('GenTransactionId', "\xC6\xAA\xD1\x5D")
MockGetMacAddress = MockFunc('GetMacAddress', "\x00\x15\x5D\x38\xAA\x38")

class TestDhcpHandler(unittest.TestCase):
 
    def test_build_dhcp_req(self):
        req = dhcphandler.BuildDhcpRequest(MockGetMacAddress())
        self.assertNotEquals(None, req)

    @Mockup(dhcphandler, "GenTransactionId", MockGenTransactionId)
    @Mockup(dhcphandler, "SocketSend", MockSocketSend)
    def test_send_dhcp_req(self):
        req = dhcphandler.BuildDhcpRequest(MockGetMacAddress())
        resp = dhcphandler.SendDhcpRequest(req)
        self.assertNotEquals(None, resp)

    @Mockup(dhcphandler, "SocketSend", MockSocketSend)
    @Mockup(dhcphandler, "GenTransactionId", MockGenTransactionId)
    @Mockup(CurrOS, "GetMacAddress", MockGetMacAddress)
    def test_handle_dhcp(self):
        dh = dhcphandler.DhcpHandler()
        dh.probe()
        self.assertEquals("10.62.144.1", dh.gateway)
        self.assertEquals("10.62.144.140", dh.endpoint)

if __name__ == '__main__':
    unittest.main()
