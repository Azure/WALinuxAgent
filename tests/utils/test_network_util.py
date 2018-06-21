# Copyright 2018 Microsoft Corporation
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

import errno
from socket import htonl


import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.networkutil as networkutil


from azurelinuxagent.common.future import ustr
from tests.tools import *


class TestNetworkOperations(AgentTestCase):
    def test_route_entry(self):
        interface = "eth0"
        mask = "C0FFFFFF"    # 255.255.255.192
        destination = "C0BB910A"    #
        gateway = "C1BB910A"
        flags = "1"
        metric = "0"

        expected = 'Iface: eth0\tDestination: 10.145.187.192\tGateway: 10.145.187.193\tMask: 255.255.255.192\tFlags: 0x0001\tMetric: 0'
        expected_json = '{"Iface": "eth0", "Destination": "10.145.187.192", "Gateway": "10.145.187.193", "Mask": "255.255.255.192", "Flags": "0x0001", "Metric": "0"}'

        entry = networkutil.RouteEntry(interface, destination, gateway, mask, flags, metric)

        self.assertEqual(str(entry), expected)
        self.assertEqual(entry.to_json(), expected_json)
