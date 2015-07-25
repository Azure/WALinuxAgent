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
from tests.tools import *
import unittest
import time
from azurelinuxagent.future import text
from azurelinuxagent.utils.osutil import OSUTIL
from azurelinuxagent.distro.default.env import EnvMonitor

class MockDhcpHandler(object):
    def conf_routes(self):
        pass

def mock_get_dhcp_pid():
    return "1234"

def mock_dhcp_pid_change():
    return text(time.time())

class TestEnvMonitor(unittest.TestCase):

    @mock(OSUTIL, 'get_dhcp_pid', mock_get_dhcp_pid)
    def test_dhcp_pid_not_change(self):
        monitor = EnvMonitor(MockDhcpHandler())
        monitor.handle_dhclient_restart()

    @mock(OSUTIL, 'get_dhcp_pid', mock_dhcp_pid_change)
    def test_dhcp_pid_change(self):
        monitor = EnvMonitor(MockDhcpHandler())
        monitor.handle_dhclient_restart()

if __name__ == '__main__':
    unittest.main()
