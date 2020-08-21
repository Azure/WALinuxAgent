# Copyright 2019 Microsoft Corporation
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

from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil
import azurelinuxagent.common.utils.shellutil as shellutil
from .test_default import osutil_get_dhcp_pid_should_return_a_list_of_pids
from tests.tools import AgentTestCase, patch # pylint: disable=wrong-import-order
import traceback # pylint: disable=wrong-import-order
import unittest # pylint: disable=wrong-import-order


class TestFreeBSDOSUtil(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        osutil_get_dhcp_pid_should_return_a_list_of_pids(self, FreeBSDOSUtil())

    def test_empty_proc_net_route(self):
        route_table = ""

        with patch.object(shellutil, 'run_command', return_value=route_table):
            # Header line only
            self.assertEqual(len(FreeBSDOSUtil().read_route_table()), 1)

    def test_no_routes(self):
        route_table = """Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
"""

        with patch.object(shellutil, 'run_command', return_value=route_table):
            raw_route_list = FreeBSDOSUtil().read_route_table()

        self.assertEqual(len(FreeBSDOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_bogus_proc_net_route(self):
        route_table = """Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
1.1.1              0.0.0
"""

        with patch.object(shellutil, 'run_command', return_value=route_table):
            raw_route_list = FreeBSDOSUtil().read_route_table()
    
        self.assertEqual(len(FreeBSDOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_valid_routes(self):
        route_table = """Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
0.0.0.0            10.145.187.193     UGS         em0       
10.145.187.192/26  0.0.0.0            US          em0       
168.63.129.16      10.145.187.193     UH          em0       
169.254.169.254    10.145.187.193     UHS         em0       
192.168.43.0       0.0.0.0            US        vtbd0     
"""

        with patch.object(shellutil, 'run_command', return_value=route_table):
            raw_route_list = FreeBSDOSUtil().read_route_table()

        self.assertEqual(len(raw_route_list), 6)

        route_list = FreeBSDOSUtil().get_list_of_routes(raw_route_list)

        self.assertEqual(len(route_list), 5)
        self.assertEqual(route_list[0].gateway_quad(), '10.145.187.193')
        self.assertEqual(route_list[1].gateway_quad(), '0.0.0.0')
        self.assertEqual(route_list[1].mask_quad(), '255.255.255.192')
        self.assertEqual(route_list[2].destination_quad(), '168.63.129.16')
        self.assertEqual(route_list[1].flags, 1)
        self.assertEqual(route_list[2].flags, 33)
        self.assertEqual(route_list[3].flags, 5)
        self.assertEqual((route_list[3].metric - route_list[4].metric), 1)
        self.assertEqual(route_list[0].interface, 'em0')
        self.assertEqual(route_list[4].interface, 'vtbd0')

    def test_get_first_if(self):
        """
        Validate that the agent can find the first active non-loopback
        interface.
        This test case used to run live, but not all developers have an eth*
        interface. It is perfectly valid to have a br*, but this test does not
        account for that.
        """
        freebsdosutil = FreeBSDOSUtil()

        with patch.object(freebsdosutil, '_get_net_info', return_value=('em0', '10.0.0.1', 'e5:f0:38:aa:da:52')):
            ifname, ipaddr = freebsdosutil.get_first_if()
        
        self.assertEqual(ifname, 'em0')
        self.assertEqual(ipaddr, '10.0.0.1')

    def test_no_primary_does_not_throw(self):
        freebsdosutil = FreeBSDOSUtil()

        with patch.object(freebsdosutil, '_get_net_info', return_value=('em0', '10.0.0.1', 'e5:f0:38:aa:da:52')):
            try:
                freebsdosutil.get_first_if()[0]
            except Exception as e: # pylint: disable=unused-variable,invalid-name
                print(traceback.format_exc())
                exception = True # pylint: disable=unused-variable

if __name__ == '__main__':
    unittest.main()
