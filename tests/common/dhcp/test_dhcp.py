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

import mock
import azurelinuxagent.common.dhcp as dhcp
import azurelinuxagent.common.osutil.default as osutil
from tests.tools import *


class TestDHCP(AgentTestCase):
    def test_wireserver_route_exists(self):
        # setup
        dhcp_handler = dhcp.get_dhcp_handler()
        self.assertTrue(dhcp_handler.endpoint is None)
        self.assertTrue(dhcp_handler.routes is None)
        self.assertTrue(dhcp_handler.gateway is None)

        # execute
        routing_table = "\
            Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	" \
                        "Mask		MTU	Window	IRTT \n\
            eth0	00000000	10813FA8	0003	0	    0	5	" \
                        "00000000	0	0	0   \n\
            eth0	00345B0A	00000000	0001	0	    0	5	" \
                        "00000000	0	0	0   \n\
            lo	    00000000	01345B0A	0003	0	    0	1	" \
                        "00FCFFFF	0	0	0   \n"

        with patch("os.path.exists", return_value=True):
            mo = mock.mock_open(read_data=routing_table)
            with patch(open_patch(), mo):
                self.assertTrue(dhcp_handler.wireserver_route_exists)

        # test
        self.assertTrue(dhcp_handler.endpoint is not None)
        self.assertTrue(dhcp_handler.routes is None)
        self.assertTrue(dhcp_handler.gateway is None)

    def test_wireserver_route_not_exists(self):
        # setup
        dhcp_handler = dhcp.get_dhcp_handler()
        self.assertTrue(dhcp_handler.endpoint is None)
        self.assertTrue(dhcp_handler.routes is None)
        self.assertTrue(dhcp_handler.gateway is None)

        # execute
        self.assertFalse(dhcp_handler.wireserver_route_exists)

        # test
        self.assertTrue(dhcp_handler.endpoint is None)
        self.assertTrue(dhcp_handler.routes is None)
        self.assertTrue(dhcp_handler.gateway is None)

    def test_dhcp_cache_exists(self):
        dhcp_handler = dhcp.get_dhcp_handler()
        dhcp_handler.osutil = osutil.DefaultOSUtil()
        with patch.object(osutil.DefaultOSUtil, 'get_dhcp_lease_endpoint',
                          return_value=None):
            self.assertFalse(dhcp_handler.dhcp_cache_exists)
            self.assertEqual(dhcp_handler.endpoint, None)
        with patch.object(osutil.DefaultOSUtil, 'get_dhcp_lease_endpoint',
                          return_value="foo"):
            self.assertTrue(dhcp_handler.dhcp_cache_exists)
            self.assertEqual(dhcp_handler.endpoint, "foo")

    def test_dhcp_skip_cache(self):
        handler = dhcp.get_dhcp_handler()
        handler.osutil = osutil.DefaultOSUtil()
        with patch('os.path.exists', return_value=False):
            with patch.object(osutil.DefaultOSUtil, 'get_dhcp_lease_endpoint')\
                    as patch_dhcp_cache:
                with patch.object(dhcp.DhcpHandler, 'send_dhcp_req') \
                        as patch_dhcp_send:

                    endpoint = 'foo'
                    patch_dhcp_cache.return_value = endpoint

                    # endpoint comes from cache
                    self.assertFalse(handler.skip_cache)
                    handler.run()
                    self.assertTrue(patch_dhcp_cache.call_count == 1)
                    self.assertTrue(patch_dhcp_send.call_count == 0)
                    self.assertTrue(handler.endpoint == endpoint)

                    # reset
                    handler.skip_cache = True
                    handler.endpoint = None

                    # endpoint comes from dhcp request
                    self.assertTrue(handler.skip_cache)
                    handler.run()
                    self.assertTrue(patch_dhcp_cache.call_count == 1)
                    self.assertTrue(patch_dhcp_send.call_count == 1)
