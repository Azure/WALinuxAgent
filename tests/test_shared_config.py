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


class TestSharedConfig(unittest.TestCase):
    
    def test_parse_shared_config(self):
        conf = waagent.SharedConfig().Parse(SharedConfigText)
        self.assertNotEquals(None, conf)
        self.assertNotEquals(None, conf.RdmaMacAddress)
        self.assertNotEquals(None, conf.RdmaIPv4Address)
        return conf

    def test_config_rdma(self):
        waagent.LoggerInit("/dev/stdout", "/dev/null", verbose=True)
        testDev = "/tmp/hvnd_rdma"
        waagent.SetFileContents(testDev, "")
        conf = self.test_parse_shared_config()
        conf.ConfigRdma(dev=testDev)
        rdmaConf = waagent.GetFileContents(testDev)
        self.assertNotEquals(None, rdmaConf)
        self.assertNotEquals("", rdmaConf)

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

if __name__ == '__main__':
    unittest.main()
