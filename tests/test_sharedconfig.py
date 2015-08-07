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

import tests.env
import tests.tools as tools
import uuid
import unittest
import os
import azurelinuxagent.protocol.v1 as v1

shared_config_sample=u"""

 <SharedConfig version="1.0.0.0" goalStateIncarnation="1">
   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
   </Deployment>
   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" settleTimeSeconds="10" />
   <LoadBalancerSettings timeoutSeconds="0" waitLoadBalancerProbeCount="8">
     <Probes>
       <Probe name="MachineRole" />
       <Probe name="55B17C5E41A1E1E8FA991CF80FAC8E55" />
       <Probe name="3EA4DBC19418F0A766A4C19D431FA45F" />
     </Probes>
   </LoadBalancerSettings>
   <OutputEndpoints>
     <Endpoint name="MachineRole:Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" type="SFS">
       <Target instance="MachineRole_IN_0" endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
     </Endpoint>
   </OutputEndpoints>
   <Instances>
     <Instance id="MachineRole_IN_0" address="10.115.153.75">
       <FaultDomains randomId="0" updateId="0" updateCount="0" />
       <InputEndpoints>
         <Endpoint name="a" address="10.115.153.75:80" protocol="http" isPublic="true" loadBalancedPublicAddress="70.37.106.197:80" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
           <LocalPorts>
             <LocalPortRange from="80" to="80" />
           </LocalPorts>
         </Endpoint>
         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" address="10.115.153.75:3389" protocol="tcp" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
           <LocalPorts>
             <LocalPortRange from="3389" to="3389" />
           </LocalPorts>
         </Endpoint>
         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput" address="10.115.153.75:20000" protocol="tcp" isPublic="true" loadBalancedPublicAddress="70.37.106.197:3389" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
           <LocalPorts>
             <LocalPortRange from="20000" to="20000" />
           </LocalPorts>
         </Endpoint>
       </InputEndpoints>
     </Instance>
   </Instances>
 </SharedConfig>
"""

class TestSharedConfig(unittest.TestCase):
    def test_sharedconfig(self):
        shared_conf = v1.SharedConfig(shared_config_sample)
   
if __name__ == '__main__':
    unittest.main()
