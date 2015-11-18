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

import unittest
from env import waagent
import sys
from tests.tools import *

class MockHTTPResponse(object):
    def __init__(self, status=200):
        self.status = status
        self.reason = "foo"

    def getheaders(*args, **kwargs):
        return {"hehe" : "haha"}

    def read(*args, **kwargs):
        return "bar"

class MockOldHTTPConnection(object):
    MockHost=None
    MockPort=None
    MockUrl=None
    MockCallCount=0

    def __init__(self, host, port):
        self.__class__.MockHost = host
        self.__class__.MockPort = port

    def request(self, method, url, data, headers = None):
        self.__class__.MockUrl = url
        self.__class__.MockCallCount += 1
    
    def getresponse(*args, **kwargs):
        return MockHTTPResponse()

class MockHTTPConnection(MockOldHTTPConnection):
    def set_tunnel(*args, **kwargs):
        pass

class MockBadHTTPConnection(MockHTTPConnection):
    def getresponse(*args, **kwargs):
        return MockHTTPResponse(500)

class MockHttpLib(object):
    def __init__(self):
        self.HTTPConnection = MockHTTPConnection
        self.OK = 200

MockOSEnv = {
        "http_proxy":"http://httpproxy:8888",
        "https_proxy":"https://httpsproxy:8888"
}

class TestHttp(unittest.TestCase):

    def test_parseurl(self):
        httputil = waagent.Util()
        host, port, secure, path = httputil._ParseUrl("http://foo:8/bar?hehe")
        self.assertEquals("foo", host)
        self.assertEquals(8, port)
        self.assertEquals(False, secure)
        self.assertEquals("/bar?hehe", path)
        
        host, port, secure, path = httputil._ParseUrl("http://foo.bar/")
        self.assertEquals("foo.bar", host)
        self.assertEquals(80, port)
        self.assertEquals(False, secure)
        self.assertEquals("/", path)

        host, port, secure, path= httputil._ParseUrl("https://foo.bar/")
        self.assertEquals("foo.bar", host)
        self.assertEquals(80, port)
        self.assertEquals(True, secure)
        self.assertEquals("/", path)

        self.assertRaises(ValueError, httputil._ParseUrl, 
                          "https://a:b@foo.bar/")

        host, port, secure, path = httputil._ParseUrl("https://foo.bar")
        self.assertEquals("foo.bar", host)
        self.assertEquals(80, port)
        self.assertEquals(True, secure)
        self.assertEquals("/", path)

        host, port, secure, path = httputil._ParseUrl("http://a:b@foo.bar:8888")
        self.assertEquals("a:b@foo.bar", host)
        self.assertEquals(8888, port)
        self.assertEquals(False, secure)
        self.assertEquals("/", path)
    
    @Mockup(waagent.httplib, "HTTPConnection", MockHTTPConnection)
    @Mockup(waagent.os, "environ", MockOSEnv)
    def test_http_request(self):
        httputil = waagent.Util()

        #If chkProxy is on, host and port should point to proxy server
        httputil.HttpRequest("GET", "http://foo.bar/get", chkProxy=True)
        self.assertEquals("httpproxy", MockHTTPConnection.MockHost) 
        self.assertEquals(8888, MockHTTPConnection.MockPort) 
        self.assertEquals("http://foo.bar:80/get", MockHTTPConnection.MockUrl) 
        
        #If chkProxy is off, ignore proxy
        httputil.HttpRequest("GET", "http://foo.bar/get", chkProxy=False)
        self.assertEquals("foo.bar", MockHTTPConnection.MockHost) 
        self.assertEquals(80, MockHTTPConnection.MockPort) 
        self.assertEquals("/get", MockHTTPConnection.MockUrl) 

    @Mockup(waagent, "httplib" , MockHttpLib())
    def test_https_fallback(self):
        httputil = waagent.Util()
        print "The bellowing warning log is expected:"
        httputil.HttpRequest("GET", "https://foo.bar/get")
        self.assertEquals("/get", MockHTTPConnection.MockUrl)

    @Mockup(waagent.httplib, "HTTPConnection", MockOldHTTPConnection)
    @Mockup(waagent.httplib, "HTTPSConnection", MockOldHTTPConnection)
    @Mockup(waagent.os, "environ", MockOSEnv)
    def test_https_fallback2(self):
        httputil = waagent.Util()
        print "The bellowing warning log is expected:"
        httputil.HttpRequest("GET", "https://foo.bar/get", chkProxy=True)
        self.assertEquals("http://foo.bar:80/get", MockOldHTTPConnection.MockUrl)

    @Mockup(waagent.Util, "RetryWaitingInterval", 0)
    @Mockup(waagent.httplib, "HTTPConnection", MockBadHTTPConnection)
    def test_retry(self):
        httputil = waagent.Util()
        MockBadHTTPConnection.MockCallCount=0
        print "The bellowing error log is expected:"
        httputil.HttpRequest("GET", "http://foo.bar", chkProxy=False, maxRetry=1)
        self.assertEquals(2, MockBadHTTPConnection.MockCallCount)
    
if __name__ == '__main__':
    unittest.main()
