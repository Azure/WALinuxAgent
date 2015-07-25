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
from .tools import *
import uuid
import unittest
import os
import shutil
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.event as evt
import azurelinuxagent.protocol as prot

class MockProtocol(object):
    def get_vminfo(self): 
        return prot.VMInfo(subscriptionId='foo', vmName='bar')
    def report_event(self, data): pass

class TestEvent(unittest.TestCase):
    def test_save(self):
        if not os.path.exists("/tmp/events"):
            os.mkdir("/tmp/events")
        evt.add_event("Test", "Test", True)
        eventsFile = os.listdir("/tmp/events")
        self.assertNotEquals(0, len(eventsFile))
        shutil.rmtree("/tmp/events")

    @mock(evt.prot.FACTORY, 'get_default_protocol', 
          MockFunc(retval=MockProtocol()))
    def test_init_sys_info(self):
        monitor = evt.EventMonitor()
        monitor.init_sysinfo()
        self.assertNotEquals(0, len(monitor.sysinfo))
        
if __name__ == '__main__':
    unittest.main()
