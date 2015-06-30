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

import os
import re
import unittest
from env import waagent

class MockDistro(object):
    def getInterfaceNameByMac(self, mac):
        pass

    def configIpV4(self, ifName, addr):
        pass

class TestSharedConfig(unittest.TestCase):

    def test_reg(self):
        mac = "00:15:5D:34:00:08"
        output = Ifconfig_Out
        output = output.replace('\n', '')
        reg = r"(eth\d).*(HWaddr|ether) {0}".format(mac)
        match = re.search(reg, output, re.IGNORECASE)
        output = match.group(0)
        eths = re.findall(r"eth\d", output)
        self.assertNotEquals(0, len(eths))
    
    def test_parse_shared_config(self):
        conf = waagent.SharedConfig().Parse(SharedConfigText)
        self.assertNotEquals(None, conf)
        self.assertNotEquals(None, conf.RdmaMacAddress)
        self.assertNotEquals(None, conf.RdmaIPv4Address)
        self.assertEquals("00:15:5D:34:00:44", conf.RdmaMacAddress)
        return conf

    def test_config_rdma(self):
        waagent.MyDistro= MockDistro()
        waagent.LibDir="/tmp"

        test_dev = "/tmp/hvnd_rdma"
        test_dat_conf_files = ["/tmp/dat.conf"]
        if os.path.isfile("/tmp/rdmaconfiged"):
            os.remove("/tmp/rdmaconfiged")
        waagent.SetFileContents(test_dev, "")
        old = ("ofa-v2-ib0 u2.0 nonthreadsafe default libdaplofa.so.2 "
               "dapl.2.0 \"oldip 0\"")
        waagent.SetFileContents(test_dat_conf_files[0], old)
        conf = self.test_parse_shared_config()
        handler = waagent.RdmaHandler(conf.RdmaMacAddress, conf.RdmaIPv4Address,
                                      test_dev, test_dat_conf_files)
        handler.set_dat_conf()
        handler.set_rdma_dev()

        rdma_conf = waagent.GetFileContents(test_dev)
        self.assertNotEquals(None, rdma_conf)
        self.assertNotEquals(0, rdma_conf.count(conf.RdmaIPv4Address))
        self.assertNotEquals(0, rdma_conf.count(conf.RdmaMacAddress))

        dat_conf = waagent.GetFileContents(test_dat_conf_files[0])
        self.assertNotEquals(None, dat_conf)
        self.assertNotEquals(0, dat_conf.count(conf.RdmaIPv4Address))
        self.assertEquals(0, dat_conf.count("oldip"))

SharedConfigText="""\
<?xml version="1.0" encoding="utf-8"?>
<SharedConfig version="1.0.0.0" goalStateIncarnation="1">
  <Deployment name="698f959e434c41cc9d72a2c67c044463" guid="{ba92e945-0302-4030-9710-257c03c07e22}" incarnation="0" isNonCancellableTopologyChangeEnabled="false">
    <Service name="test-rdms" guid="{00000000-0000-0000-0000-000000000000}" />
    <ServiceInstance name="698f959e434c41cc9d72a2c67c044463.0" guid="{6f157bcb-b6ac-4fdd-9789-2ca466220e17}" />
  </Deployment>
  <Incarnation number="1" instance="test-rdms" guid="{33d19bb6-f34d-4dfb-966c-2bade1714cc5}" />
  <Role guid="{dad0becc-5d1d-3c55-3285-0136e9933bbe}" name="test-rdms" settleTimeSeconds="0" />
  <LoadBalancerSettings timeoutSeconds="0" waitLoadBalancerProbeCount="8">
    <Probes>
      <Probe name="D41D8CD98F00B204E9800998ECF8427E" />
      <Probe name="423A4BBA20CEBE79BA641B20A03ED6F9" />
    </Probes>
  </LoadBalancerSettings>
  <OutputEndpoints>
    <Endpoint name="test-rdms:openInternalEndpoint" type="SFS">
      <Target instance="test-rdms" endpoint="openInternalEndpoint" />
    </Endpoint>
  </OutputEndpoints>
  <Instances>
    <Instance id="test-rdms" address="100.74.58.20" primaryMacAddress="000D3A101ED4" rdmaMacAddress="00155D340044" rdmaIPv4Address="172.16.2.59">
      <FaultDomains randomId="0" updateId="0" updateCount="0" />
      <InputEndpoints>
        <Endpoint name="openInternalEndpoint" address="100.74.58.20" protocol="any" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortSelfManaged />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="SSH" address="100.74.58.20:22" protocol="tcp" hostName="test-rdmsContractContract" isPublic="true" loadBalancedPublicAddress="104.45.128.35:22" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="22" to="22" />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="test-rdms_A9_Infiniband" address="100.74.58.20" protocol="any" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortSelfManaged />
          </LocalPorts>
        </Endpoint>
      </InputEndpoints>
    </Instance>
  </Instances>
</SharedConfig>
"""
Ifconfig_Out="""\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet 100.74.52.8  netmask 255.255.255.0  broadcast 100.74.52.255
inet6 fe80::20d:3aff:fe10:672f  prefixlen 64  scopeid 0x20<link>
ether 00:0d:3a:10:67:2f  txqueuelen 1000  (Ethernet)
RX packets 9911  bytes 4451278 (4.2 MiB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 10505  bytes 1643251 (1.5 MiB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet6 fe80::215:5dff:fe34:8  prefixlen 64  scopeid 0x20<link>
ether 00:15:5d:34:00:08  txqueuelen 1000  (Ethernet)
RX packets 16  bytes 672 (672.0 B)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 16  bytes 2544 (2.4 KiB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
inet 127.0.0.1  netmask 255.0.0.0
inet6 ::1  prefixlen 128  scopeid 0x10<host>
loop  txqueuelen 0  (Local Loopback)
RX packets 0  bytes 0 (0.0 B)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 0  bytes 0 (0.0 B)
"""

if __name__ == '__main__':
    unittest.main()
