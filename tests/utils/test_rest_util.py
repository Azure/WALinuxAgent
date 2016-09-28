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

import unittest
import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.future import httpclient
from tests.tools import AgentTestCase, patch, Mock, MagicMock


class TestHttpOperations(AgentTestCase):
    def test_parse_url(self):
        test_uri = "http://abc.def/ghi#hash?jkl=mn"
        host, port, secure, rel_uri = restutil._parse_url(test_uri)
        self.assertEquals("abc.def", host)
        self.assertEquals("/ghi#hash?jkl=mn", rel_uri)

        test_uri = "http://abc.def/"
        host, port, secure, rel_uri = restutil._parse_url(test_uri)
        self.assertEquals("abc.def", host)
        self.assertEquals("/", rel_uri)
        self.assertEquals(False, secure)

        test_uri = "https://abc.def/ghi?jkl=mn"
        host, port, secure, rel_uri = restutil._parse_url(test_uri)
        self.assertEquals(True, secure)

        test_uri = "http://abc.def:80/"
        host, port, secure, rel_uri = restutil._parse_url(test_uri)
        self.assertEquals("abc.def", host)

        host, port, secure, rel_uri = restutil._parse_url("")
        self.assertEquals(None, host)
        self.assertEquals(rel_uri, "")

        host, port, secure, rel_uri = restutil._parse_url("None")
        self.assertEquals(None, host)
        self.assertEquals(rel_uri, "None")

    @patch("azurelinuxagent.common.future.httpclient.HTTPSConnection")
    @patch("azurelinuxagent.common.future.httpclient.HTTPConnection")
    def test_http_request(self, HTTPConnection, HTTPSConnection):
        mock_http_conn = MagicMock()
        mock_http_resp = MagicMock()
        mock_http_conn.getresponse = Mock(return_value=mock_http_resp)
        HTTPConnection.return_value = mock_http_conn
        HTTPSConnection.return_value = mock_http_conn

        mock_http_resp.read = Mock(return_value="_(:3| <)_")

        # Test http get
        resp = restutil._http_request("GET", "foo", "bar")
        self.assertNotEquals(None, resp)
        self.assertEquals("_(:3| <)_", resp.read())

        # Test https get
        resp = restutil._http_request("GET", "foo", "bar", secure=True)
        self.assertNotEquals(None, resp)
        self.assertEquals("_(:3| <)_", resp.read())

        # Test http get with proxy
        mock_http_resp.read = Mock(return_value="_(:3| <)_")
        resp = restutil._http_request("GET", "foo", "bar", proxy_host="foo.bar",
                                      proxy_port=23333)
        self.assertNotEquals(None, resp)
        self.assertEquals("_(:3| <)_", resp.read())

        # Test https get
        resp = restutil._http_request("GET", "foo", "bar", secure=True)
        self.assertNotEquals(None, resp)
        self.assertEquals("_(:3| <)_", resp.read())

        # Test https get with proxy
        mock_http_resp.read = Mock(return_value="_(:3| <)_")
        resp = restutil._http_request("GET", "foo", "bar", proxy_host="foo.bar",
                                      proxy_port=23333, secure=True)
        self.assertNotEquals(None, resp)
        self.assertEquals("_(:3| <)_", resp.read())

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_with_retry(self, _http_request, sleep):
        mock_http_resp = MagicMock()
        mock_http_resp.read = Mock(return_value="hehe")
        _http_request.return_value = mock_http_resp

        # Test http get
        resp = restutil.http_get("http://foo.bar")
        self.assertEquals("hehe", resp.read())

        # Test https get
        resp = restutil.http_get("https://foo.bar")
        self.assertEquals("hehe", resp.read())

        # Test http failure
        _http_request.side_effect = httpclient.HTTPException("Http failure")
        self.assertRaises(restutil.HttpError, restutil.http_get,
                          "http://foo.bar")

        # Test http failure
        _http_request.side_effect = IOError("IO failure")
        self.assertRaises(restutil.HttpError, restutil.http_get,
                          "http://foo.bar")


if __name__ == '__main__':
    unittest.main()
