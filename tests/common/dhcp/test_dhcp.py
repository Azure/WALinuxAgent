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
from tests.tools import *


class TestDHCP(AgentTestCase):
    def test_wireserver_route_exists(self):
        # setup
        dhcp_handler = dhcp.get_dhcp_handler()
        self.assertIsNone(dhcp_handler.endpoint)
        self.assertIsNone(dhcp_handler.routes)
        self.assertIsNone(dhcp_handler.gateway)

        # execute
        with patch("subprocess.check_output", return_value="1"):
            self.assertTrue(dhcp_handler.wireserver_route_exists)

        # test
        self.assertIsNotNone(dhcp_handler.endpoint)
        self.assertIsNone(dhcp_handler.routes)
        self.assertIsNone(dhcp_handler.gateway)


    def test_wireserver_route_not_exists(self):
        # setup
        dhcp_handler = dhcp.get_dhcp_handler()
        self.assertIsNone(dhcp_handler.endpoint)
        self.assertIsNone(dhcp_handler.routes)
        self.assertIsNone(dhcp_handler.gateway)

        # execute
        self.assertFalse(dhcp_handler.wireserver_route_exists)

        # test
        self.assertIsNone(dhcp_handler.endpoint)
        self.assertIsNone(dhcp_handler.routes)
        self.assertIsNone(dhcp_handler.gateway)

