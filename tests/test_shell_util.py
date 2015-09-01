# -*- coding: utf-8 -*-
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
import azurelinuxagent.utils.shellutil as shellutil
import test
from azurelinuxagent.future import text

class TestrunCmd(unittest.TestCase):
    def test_run_get_output(self):
        output = shellutil.run_get_output(u"ls /")
        self.assertNotEquals(None, output)
        self.assertEquals(0, output[0])

        err = shellutil.run_get_output(u"ls /not-exists")
        self.assertNotEquals(0, err[0])
            
        err = shellutil.run_get_output(u"ls 我")
        self.assertNotEquals(0, err[0])

if __name__ == '__main__':
    unittest.main()
