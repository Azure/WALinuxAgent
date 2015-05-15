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
import azureguestagent.handler.default.deprovisionHandler as deprovisionHandler

def MockAction(param):
    print param

def MockSetup(self, deluser):
    warnings = ["Print warning to console"]
    actions = [
        deprovisionHandler.DeprovisionAction(MockAction, ['Take action'])
    ]
    return warnings, actions

class TestDeprovisionHandler(unittest.TestCase):
    def test_setUp(self):
        handler = deprovisionHandler.DeprovisionHandler()
        warnings, actions = handler.setUp(False)
        self.assertNotEquals(None, warnings)
        self.assertNotEquals(0, len(warnings))
        self.assertNotEquals(None, actions)
        self.assertNotEquals(0, len(actions))
        self.assertEquals(deprovisionHandler.DeprovisionAction, type(actions[0]))

    
    @Mockup(deprovisionHandler.DeprovisionHandler, 'setUp', MockSetup)
    def test_deprovision(self):
        handler = deprovisionHandler.DeprovisionHandler()
        handler.deprovision(force=True)

if __name__ == '__main__':
    unittest.main()
