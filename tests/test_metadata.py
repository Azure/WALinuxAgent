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
from azurelinuxagent.metadata import AGENT_NAME, AGENT_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, \
                                     DISTRO_FULL_NAME

class TestOSInfo(unittest.TestCase):
    def test_curr_os_info(self):
        self.assertNotEquals(None, DISTRO_NAME)
        self.assertNotEquals(None, DISTRO_VERSION)
        self.assertNotEquals(None, DISTRO_CODE_NAME)
        self.assertNotEquals(None, DISTRO_FULL_NAME)

if __name__ == '__main__':
    unittest.main()
