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
import test
import azurelinuxagent.protocol.v1 as v1

goal_state_sample=u"""\
<?xml version="1.0" encoding="utf-8"?>
<GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
   <Version>2010-12-15</Version>
   <Incarnation>1</Incarnation>
   <Machine>
     <ExpectedState>Started</ExpectedState>
     <LBProbePorts>
       <Port>16001</Port>
     </LBProbePorts>
   </Machine>
   <Container>
     <ContainerId>c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2</ContainerId>
     <RoleInstanceList>
       <RoleInstance>
         <InstanceId>MachineRole_IN_0</InstanceId>
         <State>Started</State>
         <Configuration>
         <HostingEnvironmentConfig>http://hostingenvuri/</HostingEnvironmentConfig>
         <SharedConfig>http://sharedconfiguri/</SharedConfig>
         <ExtensionsConfig>http://extensionsconfiguri/</ExtensionsConfig>
         <FullConfig>http://fullconfiguri/</FullConfig>
         </Configuration>
       </RoleInstance>
     </RoleInstanceList>
   </Container>
 </GoalState>
"""

class TestGoalState(unittest.TestCase):
    def test_goal_state(self):
        goal_state = v1.GoalState(goal_state_sample)
        self.assertEquals('1', goal_state.incarnation)
        self.assertNotEquals(None, goal_state.expected_state)
        self.assertNotEquals(None, goal_state.hosting_env_uri)
        self.assertNotEquals(None, goal_state.shared_conf_uri)
        self.assertEquals(None, goal_state.certs_uri)
        self.assertNotEquals(None, goal_state.ext_uri)
        self.assertNotEquals(None, goal_state.role_instance_id)
        self.assertNotEquals(None, goal_state.container_id)

if __name__ == '__main__':
    unittest.main()
