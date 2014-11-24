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
import walinuxagent.utils.restutil as restutil
import test
import socket
import walinuxagent.logger as logger

class TestHttpOperations(unittest.TestCase):

    def _setUp(self):
       logger.AddLoggerAppender(logger.AppenderConfig({
           "type":"CONSOLE",
           "level":"VERBOSE",
           "console_path":"/dev/stdout"
       }))

    def test_parse_url(self):
        host, action, secure = restutil._ParseUrl("http://abc.def/ghi?jkl=mn")
        self.assertEquals("abc.def", host)
        self.assertEquals("/ghi?jkl=mn", action)

        host, action, secure = restutil._ParseUrl("http://abc.def/")
        self.assertEquals("abc.def", host)
        self.assertEquals("/", action)
        self.assertEquals(False, secure)

        host, action, secure = restutil._ParseUrl("https://abc.def/ghi?jkl=mn")
        self.assertEquals(True, secure)

    def test_http_get(self):
        resp = restutil.HttpGet("http://httpbin.org/get").read()
        self.assertNotEquals(None, resp)
       
        msg = str(uuid.uuid4())
        resp = restutil.HttpGet("http://httpbin.org/get", {"x-abc":msg}).read()
        self.assertNotEquals(None, resp)
        self.assertTrue(msg in resp)

    def test_https_get(self):
        resp = restutil.HttpGet("https://httpbin.org/get").read()
        self.assertNotEquals(None, resp)

if __name__ == '__main__':
    unittest.main()
