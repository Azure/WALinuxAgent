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

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_status_codes(self, _http_request, _sleep):
        _http_request.side_effect = [
            Mock(status=httpclient.SERVICE_UNAVAILABLE),
            Mock(status=httpclient.OK)
        ]

        restutil.http_get("https://foo.bar")
        self.assertEqual(2, _http_request.call_count)
        self.assertEqual(1, _sleep.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_passed_status_codes(self, _http_request, _sleep):
        # Ensure the code is not part of the standard set
        self.assertFalse(httpclient.BAD_REQUEST in restutil.RETRY_CODES)

        _http_request.side_effect = [
            Mock(status=httpclient.BAD_REQUEST),
            Mock(status=httpclient.OK)
        ]

        restutil.http_get("https://foo.bar", retry_codes=[httpclient.BAD_REQUEST])
        self.assertEqual(2, _http_request.call_count)
        self.assertEqual(1, _sleep.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_exceptions(self, _http_request, _sleep):
        # Note:
        # -- It would be best to test each possible exception,
        #    but their differing signatures makes that a fair bit of work
        _http_request.side_effect = [
            httpclient.IncompleteRead(''),
            Mock(status=httpclient.OK)
        ]

        restutil.http_get("https://foo.bar")
        self.assertEqual(2, _http_request.call_count)
        self.assertEqual(1, _sleep.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_ioerrors(self, _http_request, _sleep):
        ioerror = IOError()
        
        for errno in restutil.RETRY_IOERRORS:
            _http_request.reset_mock()
            _sleep.reset_mock()

            ioerror.errno = errno

            _http_request.side_effect = [
                ioerror,
                Mock(status=httpclient.OK)
            ]

            restutil.http_get("https://foo.bar")
            self.assertEqual(2, _http_request.call_count)
            self.assertEqual(1, _sleep.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_invokes_retry_required(self, _http_request, _sleep):
        retry_count = [0]
        def retry_required(r, retry_count=retry_count):
            retry_count[0] += 1
            return retry_count[0] <= 1

        restutil.http_get("https://foo.bar", retry_required=retry_required)
        self.assertEqual(2, retry_count[0])
        self.assertEqual(2, _http_request.call_count)
        self.assertEqual(1, _sleep.call_count)
    

if __name__ == '__main__':
    unittest.main()
