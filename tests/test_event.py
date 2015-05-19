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

import env
from tools import *
import uuid
import unittest
import os
import shutil
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.event as evt

class MockInstanceMetadata(object):
    def getDeploymentName(self): return "foo"
    def getRoleName(self): return "foo"
    def getRoleInstanceId(self): return "foo"
    def getContainerId(self): return "foo"

class MockProtocol(object):
    def getInstanceMetadata(self): return MockInstanceMetadata()
    def reportEvent(self, data): pass

class TestEvent(unittest.TestCase):
    def test_toXml(self):
        event = evt.WALAEvent() 
        self.assertNotEquals(None, event.toXml())

    def test_save(self):
        if not os.path.exists("/tmp/events"):
            os.mkdir("/tmp/events")
        event = evt.WALAEvent() 
        event.save()
        eventsFile =  os.listdir("/tmp/events")
        self.assertNotEquals(0, len(eventsFile))
        shutil.rmtree("/tmp/events")

    @Mockup(evt.prot, 'GetDefaultProtocol', MockFunc(retval=MockProtocol()))
    def test_initSystemInfo(self):
        monitor = evt.WALAEventMonitor("2.1")
        self.assertNotEquals(None, monitor.sysInfo["OSVersion"])
        self.assertNotEquals(None, monitor.sysInfo["GAVersion"])
        self.assertNotEquals(None, monitor.sysInfo["RAM"])
        self.assertNotEquals(None, monitor.sysInfo["Processors"])
        self.assertNotEquals(None, monitor.sysInfo["TenantName"])
        self.assertNotEquals(None, monitor.sysInfo["RoleName"])
        self.assertNotEquals(None, monitor.sysInfo["RoleInstanceName"])
        self.assertNotEquals(None, monitor.sysInfo["ContainerId"])
    
    @Mockup(evt.prot, 'GetDefaultProtocol', MockFunc(retval=MockProtocol()))
    def test_addSystemInfo(self):
        monitor = evt.WALAEventMonitor("2.1")
        before = '<Data><Param Name="RoleName"/></Data>'
        after = monitor.addSystemInfo(before)
        self.assertEquals('<Data><Param Name="RoleName" Value="foo"/></Data>', 
                          after)
        before = evt.WALAEvent().toXml()
        after = monitor.addSystemInfo(before)
        self.assertNotEquals(None, after)
        
if __name__ == '__main__':
    unittest.main()
