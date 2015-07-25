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
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.agent as agent

class TestAgent(unittest.TestCase):
    def test_parse_args(self):
        cmd, force, verbose = agent.parse_args(["deprovision+user", 
                                               "-force", 
                                               "/verbose"])
        self.assertEquals("deprovision+user", cmd)
        self.assertTrue(force)
        self.assertTrue(verbose)

        cmd, force, verbose = agent.parse_args(["wrong cmd"])
        self.assertEquals("help", cmd)
        self.assertFalse(force)
        self.assertFalse(verbose)

if __name__ == '__main__':
    unittest.main()
