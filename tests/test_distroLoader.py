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
from tests.tools import *
import unittest
from azurelinuxagent.utils.osutil import OSUtil, OSUtilError
from azurelinuxagent.handler import Handlers
import azurelinuxagent.distro.default.osutil as osutil

class TestDistroLoader(unittest.TestCase):
    def test_loader(self):
        self.assertNotEquals(osutil.DefaultOSUtil, type(OSUtil))
        self.assertNotEquals(None, Handlers.initHandler)
        self.assertNotEquals(None, Handlers.runHandler)
        self.assertNotEquals(None, Handlers.scvmmHandler)
        self.assertNotEquals(None, Handlers.dhcpHandler)
        self.assertNotEquals(None, Handlers.envHandler)
        self.assertNotEquals(None, Handlers.provisionHandler)
        self.assertNotEquals(None, Handlers.resourceDiskHandler)
        self.assertNotEquals(None, Handlers.envHandler)
        self.assertNotEquals(None, Handlers.deprovisionHandler)

if __name__ == '__main__':
    unittest.main()
