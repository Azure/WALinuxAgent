#!/usr/bin/env python
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

import os
import os.path
import env
import ScriptUtil as su
import unittest
from MockUtil import MockUtil

class TestScriptUtil(unittest.TestCase):
    def test_parse_args(self):
        print(__file__)
        cmd = u'sh foo.bar.sh -af bar --foo=bar | more \u6211'
        args = su.parse_args(cmd.encode('utf-8'))
        self.assertNotEquals(None, args)
        self.assertNotEquals(0, len(args))
        print(args)

    def test_run_command(self):
        hutil = MockUtil(self)
        test_script = "mock.sh"
        os.chdir(os.path.join(env.root, "test"))
        exit_code = su.run_command(hutil, ["sh", test_script, "0"], os.getcwd(), 'RunScript-0', 'TestExtension', '1.0', True, 0.1)
        self.assertEquals(0, exit_code)
        self.assertEquals("do_exit", hutil.last)
        exit_code = su.run_command(hutil, ["sh", test_script, "75"], os.getcwd(), 'RunScript-1', 'TestExtension', '1.0', False, 0.1)
        self.assertEquals(75, exit_code)
        self.assertEquals("do_status_report", hutil.last)
    
    def test_log_or_exit(self):        
        hutil = MockUtil(self)
        su.log_or_exit(hutil, True, 0, 'LogOrExit-0', 'Message1')
        self.assertEquals("do_exit", hutil.last)
        su.log_or_exit(hutil, False, 0, 'LogOrExit-1', 'Message2')
        self.assertEquals("do_status_report", hutil.last)
        
if __name__ == '__main__':
    unittest.main()
