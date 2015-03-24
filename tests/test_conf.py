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
import tests.tools as tools
import uuid
import unittest
import os
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.conf as conf
import test

TestConf="""\
#
# This is comment
#
foo.bar.switch=y
foo.bar.switch2=n
foo.bar.str=foobar
foo.bar.int=300

"""

class TestConfiguration(unittest.TestCase):
    def test_parse_conf(self):
        config = conf.ConfigurationProvider(TestConf)
        self.assertEquals(True, config.getSwitch("foo.bar.switch"))
        self.assertEquals(False, config.getSwitch("foo.bar.switch2"))
        self.assertEquals(False, config.getSwitch("foo.bar.switch3"))
        self.assertEquals(True, config.getSwitch("foo.bar.switch4", True))
        self.assertEquals("foobar", config.get("foo.bar.str"))
        self.assertEquals("foobar1", config.get("foo.bar.str1", "foobar1"))
        self.assertEquals(300, config.getInt("foo.bar.int"))
        self.assertEquals(-1, config.getInt("foo.bar.int2"))
        self.assertEquals(-1, config.getInt("foo.bar.str"))

    def test_parse_malformed_conf(self):
        with self.assertRaises(Exception) as cm:
            conf.ConfigurationProvider(None)

    def test_load_conf_file(self):
        with open('/tmp/test_conf', 'w') as F:
            F.write(TestConf)
            F.close()
        
        config = conf.LoadConfiguration('/tmp/test_conf')
        self.assertNotEquals(None, config)

if __name__ == '__main__':
    unittest.main()
