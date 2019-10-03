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
import mock

from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil
import azurelinuxagent.common.utils.shellutil as shellutil
from .test_default import osutil_get_dhcp_pid_should_return_a_list_of_pids
from tests.tools import *

class TestFreeBSDOSUtil(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        osutil_get_dhcp_pid_should_return_a_list_of_pids(self, FreeBSDOSUtil())

    def test_empty_proc_net_route(self):
        with patch.object(shellutil, 'run_get_output', return_value=[0, '']):
            self.assertEqual(len(FreeBSDOSUtil().read_route_table()), 0)

    def test_no_routes(self):
        route_table = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n'

        with patch.object(shellutil, 'run_get_output', return_value=[0, route_table]):
            raw_route_list = FreeBSDOSUtil().read_route_table()

        self.assertEqual(len(FreeBSDOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_bogus_proc_net_route(self):
        route_table = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n' \
            'em0\t00000000\t00000000\t0001\t\t0\t0\n'

        with patch.object(shellutil, 'run_get_output', return_value=[0, route_table]):
            raw_route_list = FreeBSDOSUtil().read_route_table()
    
        self.assertEqual(len(FreeBSDOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_valid_routes(self):
        route_table = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n' \
            'em0\t00000000\tC1BB910A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n' \
            'em0\tC0BB910A\t00000000\t0001\t0\t0\t0\tC0FFFFFF\t0\t0\t0\n' \
            'em0\t10813FA8\tC1BB910A\t000F\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n' \
            'em0\tFEA9FEA9\tC1BB910A\t0007\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n' \
            'vtbd0\t002BA8C0\t00000000\t0001\t0\t0\t10\t00FFFFFF\t0\t0\t0\n'

        with patch.object(shellutil, 'run_get_output', return_value=[0, route_table]):
            raw_route_list = FreeBSDOSUtil().read_route_table()

        self.assertEqual(len(raw_route_list), 6)

        route_list = FreeBSDOSUtil().get_list_of_routes(raw_route_list)

        self.assertEqual(len(route_list), 5)
        self.assertEqual(route_list[0].gateway_quad(), '10.145.187.193')
        self.assertEqual(route_list[1].gateway_quad(), '0.0.0.0')
        self.assertEqual(route_list[1].mask_quad(), '255.255.255.192')
        self.assertEqual(route_list[2].destination_quad(), '168.63.129.16')
        self.assertEqual(route_list[1].flags, 1)
        self.assertEqual(route_list[2].flags, 15)
        self.assertEqual(route_list[3].flags, 7)
        self.assertEqual(route_list[3].metric, 0)
        self.assertEqual(route_list[4].metric, 10)
        self.assertEqual(route_list[0].interface, 'em0')
        self.assertEqual(route_list[4].interface, 'vtbd0')

    def test_get_first_if(self, get_all_interfaces_mock, get_primary_interface_mock):
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
            except Exception as e:
                print(traceback.format_exc())
                exception = True

if __name__ == '__main__':
    unittest.main()
