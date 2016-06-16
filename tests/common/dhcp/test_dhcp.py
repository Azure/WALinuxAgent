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
        with patch("subprocess.check_output", return_value=b'1'):
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

    def test_dhcp_lease_exists(self):
        dhcp_handler = dhcp.get_dhcp_handler()
        dhcp_handler.osutil = osutil.DefaultOSUtil()
        with patch.object(osutil.DefaultOSUtil, 'get_dhcp_lease_endpoint', return_value=None):
            self.assertFalse(dhcp_handler.dhcp_lease_exists)
            self.assertEqual(dhcp_handler.endpoint, None)
        with patch.object(osutil.DefaultOSUtil, 'get_dhcp_lease_endpoint', return_value="foo"):
            self.assertTrue(dhcp_handler.dhcp_lease_exists)
            self.assertEqual(dhcp_handler.endpoint, "foo")
