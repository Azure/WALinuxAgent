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
import json
import azurelinuxagent.protocol.v1 as v1
from azurelinuxagent.future import text

VersionInfoSample=u"""\
<?xml version="1.0" encoding="utf-8"?>
<Versions>
  <Preferred>
    <Version>2012-11-30</Version>
  </Preferred>
  <Supported>
    <Version>2010-12-15</Version>
    <Version>2010-28-10</Version>
  </Supported>
</Versions>
"""

class TestVersionInfo(unittest.TestCase):
    def test_version_info(self):
        config = v1.VersionInfo(VersionInfoSample)
        self.assertEquals("2012-11-30", config.get_preferred())
        self.assertNotEquals(None, config.get_supported())
        self.assertEquals(2, len(config.get_supported()))
        self.assertEquals("2010-12-15", config.get_supported()[0])
        self.assertEquals("2010-28-10", config.get_supported()[1])
   
if __name__ == '__main__':
    unittest.main()
