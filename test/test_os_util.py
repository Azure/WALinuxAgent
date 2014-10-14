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
import test.tools as tools
import uuid
import unittest
import os
import walinuxagent.utils.osutil as osutil
import test

class TestOSUtil(unittest.TestCase):
    def test_get_distro(self):
        distroInfo = osutil.GetDistroInfo()
        self.assertNotEquals(None, distroInfo)
        self.assertNotEquals(None, distroInfo[0])
        self.assertNotEquals(None, distroInfo[1])
        self.assertNotEquals(None, distroInfo[2])
        distro = osutil.GetDistro(distroInfo)
        self.assertNotEquals(None, distro)

    def test_current_distro(self):
        self.assertNotEquals(None, osutil.CurrentDistroInfo)
        self.assertNotEquals(None, osutil.CurrentDistro)

if __name__ == '__main__':
    unittest.main()
