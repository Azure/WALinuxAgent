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
from tests.tools import *
import uuid
import unittest
import os
import azurelinuxagent.utils.restutil as restutil
from azurelinuxagent.future import text
import test
import socket
import azurelinuxagent.logger as logger

class MockResponse(object):
    def __init__(self, status=restutil.httpclient.OK):
        self.status = status

    def getheaders(self):
        pass

class TestHttpOperations(unittest.TestCase):

    def test_parse_url(self):
        host, port, secure, rel_uri = restutil._parse_url("http://abc.def/ghi#hash?jkl=mn")
        self.assertEquals("abc.def", host)
        self.assertEquals("/ghi#hash?jkl=mn", rel_uri)

        host, port, secure, rel_uri = restutil._parse_url("http://abc.def/")
        self.assertEquals("abc.def", host)
        self.assertEquals("/", rel_uri)
        self.assertEquals(False, secure)

        host, port, secure, rel_uri = restutil._parse_url("https://abc.def/ghi?jkl=mn")
        self.assertEquals(True, secure)

        host, port, secure, rel_uri = restutil._parse_url("http://abc.def:80/")
        self.assertEquals("abc.def", host)

    @mock(restutil.httpclient.HTTPConnection, 'request', MockFunc())
    @mock(restutil.httpclient.HTTPConnection, 'getresponse', MockFunc(retval=MockResponse()))
    def test_http_request(self):
        restutil.http_get("https://httpbin.org/get")
    
if __name__ == '__main__':
    unittest.main()
