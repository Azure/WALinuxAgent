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

hosting_env_sample=u"""
 <HostingEnvironmentConfig version="1.0.0.0" goalStateIncarnation="1">
   <StoredCertificates>
     <StoredCertificate name="Stored0Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption" certificateId="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" storeName="My" configurationLevel="System" />
   </StoredCertificates>
   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
   </Deployment>
   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" hostingEnvironmentVersion="1" software="" softwareType="ApplicationPackage" entryPoint="" parameters="" settleTimeSeconds="10" />
   <HostingEnvironmentSettings name="full" runtime="rd_fabric_stable.110217-1402.runtimePackage_1.0.0.8.zip">
     <CAS mode="full" />
     <PrivilegeLevel mode="max" />
     <AdditionalProperties><CgiHandlers></CgiHandlers></AdditionalProperties>
   </HostingEnvironmentSettings>
   <ApplicationSettings>
     <Setting name="__ModelData" value="&lt;m role=&quot;MachineRole&quot; xmlns=&quot;urn:azure:m:v1&quot;>&lt;r name=&quot;MachineRole&quot;>&lt;e name=&quot;a&quot; />&lt;e name=&quot;b&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput&quot; />&lt;/r>&lt;/m>" />
     <Setting name="Microsoft.WindowsAzure.Plugins.Diagnostics.ConnectionString" value="DefaultEndpointsProtocol=http;AccountName=osimages;AccountKey=DNZQ..." />
     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.Enabled" value="true" />
   </ApplicationSettings>
   <ResourceReferences>
     <Resource name="DiagnosticStore" type="directory" request="Microsoft.Cis.Fabric.Controller.Descriptions.ServiceDescription.Data.Policy" sticky="true" size="1" path="db00a7755a5e4e8a8fe4b19bc3b330c3.MachineRole.DiagnosticStore\" disableQuota="false" />
   </ResourceReferences>
 </HostingEnvironmentConfig>
"""

class TestHostingEvn(unittest.TestCase):
    def test_hosting_env(self):
        hosting_env = v1.HostingEnv(hosting_env_sample)
        self.assertNotEquals(None, hosting_env)
        self.assertEquals("MachineRole_IN_0", hosting_env.vm_name)
        self.assertEquals("MachineRole", hosting_env.role_name)
        self.assertEquals("db00a7755a5e4e8a8fe4b19bc3b330c3", 
                          hosting_env.deployment_name)

   
if __name__ == '__main__':
    unittest.main()
