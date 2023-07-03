#!/usr/bin/env python
#
# Sample Extension
#
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

import unittest
import HandlerUtil as Util

def mock_log(*args, **kwargs):
    pass

class TestNullProtectedSettings(unittest.TestCase):
    def test_null_protected_settings(self):
        hutil = Util.HandlerUtility(mock_log, mock_log, "UnitTest", "HandlerUtil.UnitTest", "0.0.1")
        config = hutil._parse_config(Settings)
        handlerSettings = config['runtimeSettings'][0]['handlerSettings']
        self.assertEquals(handlerSettings["protectedSettings"], None)

Settings="""\
{
    "runtimeSettings":[{
        "handlerSettings":{
            "protectedSettingsCertThumbprint":null,
            "protectedSettings":null,
            "publicSettings":{}
            }
     }]
}
"""

if __name__ == '__main__':
    unittest.main()
