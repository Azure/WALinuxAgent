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
from tools import *
import uuid
import shutil
import unittest
import os
import azureguestagent.logger as logger
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.utils.textutil as textutil
from azureguestagent.utils.osutil import CurrOSInfo, CurrOS
import test

"""
OS related test. Need to run with root privilege.

CAUSION: during the test, user account and system config may be changed
"""
class TestUserOperation(unittest.TestCase):
    def test_sysuser(self):
        self.assertTrue(CurrOS.IsSysUser('root')) 

    def test_update_user_account(self):
        userName="nobodywillusethisname"
        shellutil.Run('userdel -f -r ' + userName)
        self.assertFalse(tools.simple_file_grep('/etc/passwd', userName))
        self.assertFalse(os.path.isdir(os.path.join(CurrOS.GetHome(), userName)))

        CurrOS.UpdateUserAccount(userName, "User@123")
        self.assertTrue(tools.simple_file_grep('/etc/passwd', userName))
        self.assertTrue(tools.simple_file_grep('/etc/sudoers.d/waagent',
                                               userName))
        self.assertTrue(os.path.isdir(os.path.join(CurrOS.GetHome(), userName)))

class TestSshOperation(unittest.TestCase):
    def _setUp(self):
       logger.AddLoggerAppender(logger.AppenderConfig({
           "type":"CONSOLE",
           "level":"VERBOSE",
           "console_path":"/dev/stdout"
       }))

    def test_regen_ssh_host_key(self):
        oldKey = fileutil.GetFileContents('/etc/ssh/ssh_host_rsa_key')
        CurrOS.RegenerateSshHostkey('rsa')
        newKey = fileutil.GetFileContents('/etc/ssh/ssh_host_rsa_key')
        self.assertNotEquals(oldKey, newKey)

    #TODO test dvd mount
    #TODO test set scsi
    #TODO test set/publish hostname

if __name__ == '__main__':
    unittest.main()
