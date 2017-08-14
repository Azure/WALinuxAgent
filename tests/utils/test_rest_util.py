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

from azurelinuxagent.common.exception import BadRequestError, \
                                        HttpError, ProtocolError
import azurelinuxagent.common.utils.restutil as restutil

from azurelinuxagent.common.future import httpclient, ustr
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
        self.assertFalse(httpclient.UNAUTHORIZED in restutil.RETRY_CODES)

        _http_request.side_effect = [
            Mock(status=httpclient.UNAUTHORIZED),
            Mock(status=httpclient.OK)
        ]

        restutil.http_get("https://foo.bar", retry_codes=[httpclient.UNAUTHORIZED])
        self.assertEqual(2, _http_request.call_count)
        self.assertEqual(1, _sleep.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_raises_for_bad_request(self, _http_request, _sleep):
        _http_request.side_effect = [
            Mock(status=httpclient.BAD_REQUEST)
        ]

        self.assertRaises(BadRequestError, restutil.http_get, "https://foo.bar")
        self.assertEqual(1, _http_request.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_exceptions(self, _http_request, _sleep):
        # Testing each exception is difficult because they have varying
        # signatures; for now, test one and ensure the set is unchanged
        recognized_exceptions = [
            httpclient.NotConnected,
            httpclient.IncompleteRead,
            httpclient.ImproperConnectionState,
            httpclient.BadStatusLine
        ]
        self.assertEqual(recognized_exceptions, restutil.RETRY_EXCEPTIONS)

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

    def test_request_failed(self):
        self.assertTrue(restutil.request_failed(None))

        resp = Mock()
        for status in restutil.OK_CODES:
            resp.status = status
            self.assertFalse(restutil.request_failed(resp))

        self.assertFalse(httpclient.BAD_REQUEST in restutil.OK_CODES)
        resp.status = httpclient.BAD_REQUEST
        self.assertTrue(restutil.request_failed(resp))

        self.assertFalse(
            restutil.request_failed(
                resp, ok_codes=[httpclient.BAD_REQUEST]))

    def test_request_succeeded(self):
        self.assertFalse(restutil.request_succeeded(None))

        resp = Mock()
        for status in restutil.OK_CODES:
            resp.status = status
            self.assertTrue(restutil.request_succeeded(resp))

        self.assertFalse(httpclient.BAD_REQUEST in restutil.OK_CODES)
        resp.status = httpclient.BAD_REQUEST
        self.assertFalse(restutil.request_succeeded(resp))

        self.assertTrue(
            restutil.request_succeeded(
                resp, ok_codes=[httpclient.BAD_REQUEST]))

    def test_read_response_error(self):
        """
        Validate the read_response_error method handles encoding correctly
        """
        responses = ['message', b'message', '\x80message\x80']
        response = MagicMock()
        response.status = 'status'
        response.reason = 'reason'
        with patch.object(response, 'read') as patch_response:
            for s in responses:
                patch_response.return_value = s
                result = restutil.read_response_error(response)
                print("RESPONSE: {0}".format(s))
                print("RESULT: {0}".format(result))
                print("PRESENT: {0}".format('[status: reason]' in result))
                self.assertTrue('[status: reason]' in result)
                self.assertTrue('message' in result)

    def test_read_response_bytes(self):
        response_bytes = '7b:0a:20:20:20:20:22:65:72:72:6f:72:43:6f:64:65:22:' \
                         '3a:20:22:54:68:65:20:62:6c:6f:62:20:74:79:70:65:20:' \
                         '69:73:20:69:6e:76:61:6c:69:64:20:66:6f:72:20:74:68:' \
                         '69:73:20:6f:70:65:72:61:74:69:6f:6e:2e:22:2c:0a:20:' \
                         '20:20:20:22:6d:65:73:73:61:67:65:22:3a:20:22:c3:af:' \
                         'c2:bb:c2:bf:3c:3f:78:6d:6c:20:76:65:72:73:69:6f:6e:' \
                         '3d:22:31:2e:30:22:20:65:6e:63:6f:64:69:6e:67:3d:22:' \
                         '75:74:66:2d:38:22:3f:3e:3c:45:72:72:6f:72:3e:3c:43:' \
                         '6f:64:65:3e:49:6e:76:61:6c:69:64:42:6c:6f:62:54:79:' \
                         '70:65:3c:2f:43:6f:64:65:3e:3c:4d:65:73:73:61:67:65:' \
                         '3e:54:68:65:20:62:6c:6f:62:20:74:79:70:65:20:69:73:' \
                         '20:69:6e:76:61:6c:69:64:20:66:6f:72:20:74:68:69:73:' \
                         '20:6f:70:65:72:61:74:69:6f:6e:2e:0a:52:65:71:75:65:' \
                         '73:74:49:64:3a:63:37:34:32:39:30:63:62:2d:30:30:30:' \
                         '31:2d:30:30:62:35:2d:30:36:64:61:2d:64:64:36:36:36:' \
                         '61:30:30:30:22:2c:0a:20:20:20:20:22:64:65:74:61:69:' \
                         '6c:73:22:3a:20:22:22:0a:7d'.split(':')
        expected_response = '[HTTP Failed] [status: reason] {\n    "errorCode": "The blob ' \
                            'type is invalid for this operation.",\n    ' \
                            '"message": "<?xml version="1.0" ' \
                            'encoding="utf-8"?>' \
                            '<Error><Code>InvalidBlobType</Code><Message>The ' \
                            'blob type is invalid for this operation.\n' \
                            'RequestId:c74290cb-0001-00b5-06da-dd666a000",' \
                            '\n    "details": ""\n}'

        response_string = ''.join(chr(int(b, 16)) for b in response_bytes)
        response = MagicMock()
        response.status = 'status'
        response.reason = 'reason'
        with patch.object(response, 'read') as patch_response:
            patch_response.return_value = response_string
            result = restutil.read_response_error(response)
            self.assertEqual(result, expected_response)
            try:
                raise HttpError("{0}".format(result))
            except HttpError as e:
                self.assertTrue(result in ustr(e))


if __name__ == '__main__':
    unittest.main()
