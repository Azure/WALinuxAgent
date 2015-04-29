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

import unittest
from env import waagent
import sys
from tests.tools import *

SampleInterfaceInfo="""\
eth0      Link encap:Ethernet  HWaddr ff:ff:ff:ff:ff:ff  
          inet addr:10.94.20.249  Bcast:10.94.23.255  Mask:255.255.252.0
          inet6 addr: fe80::215:5dff:fe5f:bf03/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3789880 errors:0 dropped:0 overruns:0 frame:0
          TX packets:80973 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:388563383 (388.5 MB)  TX bytes:21484571 (21.4 MB)

eth1      Link encap:Ethernet  HWaddr 00:00:00:00:00:00  
          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0
          inet6 addr: fe80::215:5dff:fe5f:bf08/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:386614 errors:0 dropped:0 overruns:0 frame:0
          TX packets:201356 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:32507619 (32.5 MB)  TX bytes:78342503 (78.3 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:2561 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2561 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
"""

class TestUtil(unittest.TestCase):

    @Mockup(waagent, "RunGetOutput", MockFunc('', (0, SampleInterfaceInfo)))
    def test_getInterfaceNameByMac(self):
        distro = waagent.AbstractDistro()
        ifName = distro.getInterfaceNameByMac("ff:ff:ff:ff:ff:ff")
        self.assertEquals("eth0", ifName)
        ifName = distro.getInterfaceNameByMac("00:00:00:00:00:00")
        self.assertEquals("eth1", ifName)
        

if __name__ == '__main__':
    unittest.main()
