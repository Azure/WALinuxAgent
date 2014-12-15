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
import json
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.protocol as proto
import walinuxagent.extension as ext
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo

setting = proto.ExtensionInfo({
    "name":"TestExt",
    "properties":{
        "version":"2.1",
        "upgrade-policy":"auto",
        "versionUris":[{
            "version":"2.1",
            "uris":["http://foo.bar"]
        },{
            "version":"2.0",
            "uris":["http://foo.bar"]
        }]
    }
})

class TestExtensions(unittest.TestCase):
    
    def test_load_ext(self):
        libDir = CurrOS.GetLibDir()
        testExt1 = os.path.join(libDir, 'TestExt-1.0')
        testExt2 = os.path.join(libDir, 'TestExt-2.0')
        for path in {testExt1, testExt2}:
            if not os.path.isdir(path):
                os.mkdir(path)
        testExt = ext.LoadExtensionInstance(setting)
        self.assertNotEqual(None, testExt)

if __name__ == '__main__':
    unittest.main()
