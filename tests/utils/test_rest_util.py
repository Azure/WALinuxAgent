# Copyright 2018 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import unittest
from datetime import datetime, timedelta
from random import randint

from azurelinuxagent.common.exception import HttpError, ResourceGoneError, InvalidContainerError
import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.utils.restutil import HTTP_USER_AGENT
from azurelinuxagent.common.future import httpclient, ustr
from tests.protocol.mocks import MockHttpResponse
from tests.tools import AgentTestCase, call, Mock, MagicMock, patch


class TestIOErrorCounter(AgentTestCase):
    def test_increment_hostplugin(self):
        restutil.IOErrorCounter.reset()
        restutil.IOErrorCounter.set_protocol_endpoint()

        restutil.IOErrorCounter.increment(
            restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

        counts = restutil.IOErrorCounter.get_and_reset()
        self.assertEqual(1, counts["hostplugin"])
        self.assertEqual(0, counts["protocol"])
        self.assertEqual(0, counts["other"])

    def test_increment_protocol(self):
        restutil.IOErrorCounter.reset()
        restutil.IOErrorCounter.set_protocol_endpoint()

        restutil.IOErrorCounter.increment(
            restutil.KNOWN_WIRESERVER_IP, 80)

        counts = restutil.IOErrorCounter.get_and_reset()
        self.assertEqual(0, counts["hostplugin"])
        self.assertEqual(1, counts["protocol"])
        self.assertEqual(0, counts["other"])

    def test_increment_other(self):
        restutil.IOErrorCounter.reset()
        restutil.IOErrorCounter.set_protocol_endpoint()

        restutil.IOErrorCounter.increment(
            '169.254.169.254', 80)

        counts = restutil.IOErrorCounter.get_and_reset()
        self.assertEqual(0, counts["hostplugin"])
        self.assertEqual(0, counts["protocol"])
        self.assertEqual(1, counts["other"])

    def test_get_and_reset(self):
        restutil.IOErrorCounter.reset()
        restutil.IOErrorCounter.set_protocol_endpoint()

        restutil.IOErrorCounter.increment(
            restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)
        restutil.IOErrorCounter.increment(
            restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)
        restutil.IOErrorCounter.increment(
            restutil.KNOWN_WIRESERVER_IP, 80)
        restutil.IOErrorCounter.increment(
            '169.254.169.254', 80)
        restutil.IOErrorCounter.increment(
            '169.254.169.254', 80)

        counts = restutil.IOErrorCounter.get_and_reset()
        self.assertEqual(2, counts.get("hostplugin"))
        self.assertEqual(1, counts.get("protocol"))
        self.assertEqual(2, counts.get("other"))
        self.assertEqual(
           {"hostplugin":0, "protocol":0, "other":0},
            restutil.IOErrorCounter._counts) # pylint: disable=protected-access


class TestHttpOperations(AgentTestCase): # pylint: disable=too-many-public-methods
    def test_parse_url(self):
        test_uri = "http://abc.def/ghi#hash?jkl=mn"
        host, port, secure, rel_uri = restutil._parse_url(test_uri) # pylint: disable=unused-variable,protected-access
        self.assertEqual("abc.def", host) 
        self.assertEqual("/ghi#hash?jkl=mn", rel_uri) 

        test_uri = "http://abc.def/"
        host, port, secure, rel_uri = restutil._parse_url(test_uri) # pylint: disable=protected-access
        self.assertEqual("abc.def", host) 
        self.assertEqual("/", rel_uri) 
        self.assertEqual(False, secure) 

        test_uri = "https://abc.def/ghi?jkl=mn"
        host, port, secure, rel_uri = restutil._parse_url(test_uri) # pylint: disable=protected-access
        self.assertEqual(True, secure) 

        test_uri = "http://abc.def:80/"
        host, port, secure, rel_uri = restutil._parse_url(test_uri) # pylint: disable=protected-access
        self.assertEqual("abc.def", host) 

        host, port, secure, rel_uri = restutil._parse_url("") # pylint: disable=protected-access
        self.assertEqual(None, host) 
        self.assertEqual(rel_uri, "") 

        host, port, secure, rel_uri = restutil._parse_url("None") # pylint: disable=protected-access
        self.assertEqual(None, host) 
        self.assertEqual(rel_uri, "None") 

    def test_cleanup_sas_tokens_from_urls_for_normal_cases(self):
        test_url = "http://abc.def/ghi#hash?jkl=mn"
        filtered_url = restutil.redact_sas_tokens_in_urls(test_url)
        self.assertEqual(test_url, filtered_url) 

        test_url = "http://abc.def:80/"
        filtered_url = restutil.redact_sas_tokens_in_urls(test_url)
        self.assertEqual(test_url, filtered_url) 

        test_url = "http://abc.def/"
        filtered_url = restutil.redact_sas_tokens_in_urls(test_url)
        self.assertEqual(test_url, filtered_url) 

        test_url = "https://abc.def/ghi?jkl=mn"
        filtered_url = restutil.redact_sas_tokens_in_urls(test_url)
        self.assertEqual(test_url, filtered_url) 

    def test_cleanup_sas_tokens_from_urls_containing_sas_tokens(self):
        # Contains pair of URLs (RawURL, RedactedURL)
        urls_tuples = [("https://abc.def.xyz.123.net/functiontest/yokawasa.png?sig"
                        "=sXBjML1Fpk9UnTBtajo05ZTFSk0LWFGvARZ6WlVcAog%3D&srt=o&ss=b&"
                        "spr=https&sp=rl&sv=2016-05-31&se=2017-07-01T00%3A21%3A38Z&"
                        "st=2017-07-01T23%3A16%3A38Z",
                        "https://abc.def.xyz.123.net/functiontest/yokawasa.png?sig"
                        "=" + restutil.REDACTED_TEXT +
                        "&srt=o&ss=b&spr=https&sp=rl&sv=2016-05-31&se=2017-07-01T00"
                        "%3A21%3A38Z&st=2017-07-01T23%3A16%3A38Z"),
                       ("https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se=2018-07"
                        "-26T02:20:44Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=DavQgRtl99DsEPv9Xeb63GnLXCuaLYw5ay%2BE1cFckQY%3D",
                        "https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se"
                        "=2018-07-26T02:20:44Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=" + restutil.REDACTED_TEXT),
                       ("https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se=2018-07"
                        "-26T02:20:44Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=ttSCKmyjiDEeIzT9q7HtYYgbCRIXuesFSOhNEab52NM%3D",
                        "https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se"
                        "=2018-07-26T02:20:44Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=" + restutil.REDACTED_TEXT),
                       ("https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se=2018-07"
                        "-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=X0imGmcj5KcBPFcqlfYjIZakzGrzONGbRv5JMOnGrwc%3D",
                        "https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se"
                        "=2018-07-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=" + restutil.REDACTED_TEXT),
                       ("https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se=2018-07"
                        "-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=9hfxYvaZzrMahtGO1OgMUiFGnDOtZXulZ3skkv1eVBg%3D",
                        "https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se"
                        "=2018-07-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https,"
                        "http&sig=" + restutil.REDACTED_TEXT),
                       ("https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se=2018-07"
                        "-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https"
                        "&sig=cmluQEHnOGsVK9NDm83ruuPdPWNQcerfjOAbkspNZXU%3D",
                        "https://abc.def.xyz.123.net/?sv=2017-11-09&ss=b&srt=o&sp=r&se"
                        "=2018-07-26T02:20:42Z&st=2018-07-25T18:20:44Z&spr=https&sig"
                        "=" + restutil.REDACTED_TEXT)
                       ]

        for x in urls_tuples: # pylint: disable=invalid-name
            self.assertEqual(restutil.redact_sas_tokens_in_urls(x[0]), x[1]) 

    @patch('azurelinuxagent.common.conf.get_httpproxy_port')
    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_none_is_default(self, mock_host, mock_port):
        mock_host.return_value = None
        mock_port.return_value = None
        h, p = restutil._get_http_proxy() # pylint: disable=protected-access,invalid-name
        self.assertEqual(None, h)
        self.assertEqual(None, p)

    @patch('azurelinuxagent.common.conf.get_httpproxy_port')
    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_configuration_overrides_env(self, mock_host, mock_port):
        mock_host.return_value = "host"
        mock_port.return_value = None
        h, p = restutil._get_http_proxy() # pylint: disable=protected-access,invalid-name
        self.assertEqual("host", h)
        self.assertEqual(None, p)
        self.assertEqual(1, mock_host.call_count)
        self.assertEqual(1, mock_port.call_count)

    @patch('azurelinuxagent.common.conf.get_httpproxy_port')
    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_configuration_requires_host(self, mock_host, mock_port):
        mock_host.return_value = None
        mock_port.return_value = None
        h, p = restutil._get_http_proxy() # pylint: disable=protected-access,invalid-name
        self.assertEqual(None, h)
        self.assertEqual(None, p)
        self.assertEqual(1, mock_host.call_count)
        self.assertEqual(0, mock_port.call_count)

    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_http_uses_httpproxy(self, mock_host):
        mock_host.return_value = None
        with patch.dict(os.environ, {
                                    'http_proxy' : 'http://foo.com:80',
                                    'https_proxy' : 'https://bar.com:443'
                                }):
            h, p = restutil._get_http_proxy() # pylint: disable=protected-access,invalid-name
            self.assertEqual("foo.com", h)
            self.assertEqual(80, p)

    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_https_uses_httpsproxy(self, mock_host):
        mock_host.return_value = None
        with patch.dict(os.environ, {
                                    'http_proxy' : 'http://foo.com:80',
                                    'https_proxy' : 'https://bar.com:443'
                                }):
            h, p = restutil._get_http_proxy(secure=True) # pylint: disable=protected-access,invalid-name
            self.assertEqual("bar.com", h)
            self.assertEqual(443, p)

    @patch('azurelinuxagent.common.conf.get_httpproxy_host')
    def test_get_http_proxy_ignores_user_in_httpproxy(self, mock_host):
        mock_host.return_value = None
        with patch.dict(os.environ, {
                                    'http_proxy' : 'http://user:pw@foo.com:80'
                                }):
            h, p = restutil._get_http_proxy() # pylint: disable=protected-access,invalid-name
            self.assertEqual("foo.com", h)
            self.assertEqual(80, p)

    def test_get_no_proxy_with_values_set(self):
        no_proxy_list = ["foo.com", "www.google.com"]
        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            no_proxy_from_environment = restutil.get_no_proxy()

            self.assertEqual(len(no_proxy_list), len(no_proxy_from_environment)) 

            for i, j in zip(no_proxy_from_environment, no_proxy_list):
                self.assertEqual(i, j)

    def test_get_no_proxy_with_incorrect_variable_set(self):
        no_proxy_list = ["foo.com", "www.google.com", "", ""]
        no_proxy_list_cleaned = [entry for entry in no_proxy_list if entry]

        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            no_proxy_from_environment = restutil.get_no_proxy()

            self.assertEqual(len(no_proxy_list_cleaned), len(no_proxy_from_environment)) 

            for i, j in zip(no_proxy_from_environment, no_proxy_list_cleaned):
                print(i, j)
                self.assertEqual(i, j)

    def test_get_no_proxy_with_ip_addresses_set(self):
        no_proxy_var = "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8,10.0.0.9,10.0.0.10,"
        no_proxy_list = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5',
                         '10.0.0.6', '10.0.0.7', '10.0.0.8', '10.0.0.9', '10.0.0.10']

        with patch.dict(os.environ, {
            'no_proxy': no_proxy_var
        }):
            no_proxy_from_environment = restutil.get_no_proxy()

            self.assertEqual(len(no_proxy_list), len(no_proxy_from_environment)) 

            for i, j in zip(no_proxy_from_environment, no_proxy_list):
                self.assertEqual(i, j)

    def test_get_no_proxy_default(self):
        no_proxy_generator = restutil.get_no_proxy()
        self.assertIsNone(no_proxy_generator)

    def test_is_ipv4_address(self):
        self.assertTrue(restutil.is_ipv4_address('8.8.8.8'))
        self.assertFalse(restutil.is_ipv4_address('localhost.localdomain'))
        self.assertFalse(restutil.is_ipv4_address('2001:4860:4860::8888')) # ipv6 tests

    def test_is_valid_cidr(self):
        self.assertTrue(restutil.is_valid_cidr('192.168.1.0/24'))
        self.assertFalse(restutil.is_valid_cidr('8.8.8.8'))
        self.assertFalse(restutil.is_valid_cidr('192.168.1.0/a'))
        self.assertFalse(restutil.is_valid_cidr('192.168.1.0/128'))
        self.assertFalse(restutil.is_valid_cidr('192.168.1.0/-1'))
        self.assertFalse(restutil.is_valid_cidr('192.168.1.999/24'))

    def test_address_in_network(self):
        self.assertTrue(restutil.address_in_network('192.168.1.1', '192.168.1.0/24'))
        self.assertFalse(restutil.address_in_network('172.16.0.1', '192.168.1.0/24'))

    def test_dotted_netmask(self):
        self.assertEqual(restutil.dotted_netmask(0), '0.0.0.0') 
        self.assertEqual(restutil.dotted_netmask(8), '255.0.0.0') 
        self.assertEqual(restutil.dotted_netmask(16), '255.255.0.0') 
        self.assertEqual(restutil.dotted_netmask(24), '255.255.255.0') 
        self.assertEqual(restutil.dotted_netmask(32), '255.255.255.255') 
        self.assertRaises(ValueError, restutil.dotted_netmask, 33)

    def test_bypass_proxy(self):
        no_proxy_list = ["foo.com", "www.google.com", "168.63.129.16", "Microsoft.com"]
        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            self.assertFalse(restutil.bypass_proxy("http://bar.com"))
            self.assertTrue(restutil.bypass_proxy("http://foo.com"))
            self.assertTrue(restutil.bypass_proxy("http://168.63.129.16"))
            self.assertFalse(restutil.bypass_proxy("http://baz.com"))
            self.assertFalse(restutil.bypass_proxy("http://10.1.1.1"))
            self.assertTrue(restutil.bypass_proxy("http://www.microsoft.com"))

    @patch("azurelinuxagent.common.future.httpclient.HTTPSConnection")
    @patch("azurelinuxagent.common.future.httpclient.HTTPConnection")
    def test_http_request_direct(self, HTTPConnection, HTTPSConnection): # pylint: disable=invalid-name
        mock_conn = \
            MagicMock(getresponse=\
                Mock(return_value=\
                    Mock(read=Mock(return_value="TheResults"))))

        HTTPConnection.return_value = mock_conn

        resp = restutil._http_request("GET", "foo", "/bar") # pylint: disable=protected-access

        HTTPConnection.assert_has_calls([
            call("foo", 80, timeout=10)
        ])
        HTTPSConnection.assert_not_called()
        mock_conn.request.assert_has_calls([
            call(method="GET", url="/bar", body=None, headers={'User-Agent': HTTP_USER_AGENT, 'Connection': 'close'})
        ])
        self.assertEqual(1, mock_conn.getresponse.call_count)
        self.assertNotEqual(None, resp) 
        self.assertEqual("TheResults", resp.read()) 

    @patch("azurelinuxagent.common.future.httpclient.HTTPSConnection")
    @patch("azurelinuxagent.common.future.httpclient.HTTPConnection")
    def test_http_request_direct_secure(self, HTTPConnection, HTTPSConnection): # pylint: disable=invalid-name
        mock_conn = \
            MagicMock(getresponse=\
                Mock(return_value=\
                    Mock(read=Mock(return_value="TheResults"))))

        HTTPSConnection.return_value = mock_conn

        resp = restutil._http_request("GET", "foo", "/bar", secure=True) # pylint: disable=protected-access

        HTTPConnection.assert_not_called()
        HTTPSConnection.assert_has_calls([
            call("foo", 443, timeout=10)
        ])
        mock_conn.request.assert_has_calls([
            call(method="GET", url="/bar", body=None, headers={'User-Agent': HTTP_USER_AGENT, 'Connection': 'close'})
        ])
        self.assertEqual(1, mock_conn.getresponse.call_count)
        self.assertNotEqual(None, resp) 
        self.assertEqual("TheResults", resp.read()) 

    @patch("azurelinuxagent.common.future.httpclient.HTTPSConnection")
    @patch("azurelinuxagent.common.future.httpclient.HTTPConnection")
    def test_http_request_proxy(self, HTTPConnection, HTTPSConnection): # pylint: disable=invalid-name
        mock_conn = \
            MagicMock(getresponse=\
                Mock(return_value=\
                    Mock(read=Mock(return_value="TheResults"))))

        HTTPConnection.return_value = mock_conn

        resp = restutil._http_request("GET", "foo", "/bar", # pylint: disable=protected-access
                            proxy_host="foo.bar", proxy_port=23333)

        HTTPConnection.assert_has_calls([
            call("foo.bar", 23333, timeout=10)
        ])
        HTTPSConnection.assert_not_called()
        mock_conn.request.assert_has_calls([
            call(method="GET", url="http://foo:80/bar", body=None, headers={'User-Agent': HTTP_USER_AGENT, 'Connection': 'close'})
        ])
        self.assertEqual(1, mock_conn.getresponse.call_count)
        self.assertNotEqual(None, resp) 
        self.assertEqual("TheResults", resp.read()) 

    @patch("azurelinuxagent.common.utils.restutil._get_http_proxy")
    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_proxy_with_no_proxy_check(self, _http_request, sleep, mock_get_http_proxy): # pylint: disable=unused-argument
        mock_http_resp = MagicMock()
        mock_http_resp.read = Mock(return_value="hehe")
        _http_request.return_value = mock_http_resp
        mock_get_http_proxy.return_value = "host", 1234 # Return a host/port combination

        no_proxy_list = ["foo.com", "www.google.com", "168.63.129.16"]
        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            # Test http get
            resp = restutil.http_get("http://foo.com", use_proxy=True)
            self.assertEqual("hehe", resp.read()) 
            self.assertEqual(0, mock_get_http_proxy.call_count) 

            # Test http get
            resp = restutil.http_get("http://bar.com", use_proxy=True)
            self.assertEqual("hehe", resp.read()) 
            self.assertEqual(1, mock_get_http_proxy.call_count) 

    def test_proxy_conditions_with_no_proxy(self):
        should_use_proxy = True
        should_not_use_proxy = False
        use_proxy = True

        no_proxy_list = ["foo.com", "www.google.com", "168.63.129.16"]
        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            host = "10.0.0.1"
            self.assertEqual(should_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "foo.com"
            self.assertEqual(should_not_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "www.google.com"
            self.assertEqual(should_not_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "168.63.129.16"
            self.assertEqual(should_not_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "www.bar.com"
            self.assertEqual(should_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

        no_proxy_list = ["10.0.0.1/24"]
        with patch.dict(os.environ, {
            'no_proxy': ",".join(no_proxy_list)
        }):
            host = "www.bar.com"
            self.assertEqual(should_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "10.0.0.1"
            self.assertEqual(should_not_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

            host = "10.0.1.1"
            self.assertEqual(should_use_proxy, use_proxy and not restutil.bypass_proxy(host)) 

        # When No_proxy is empty
        with patch.dict(os.environ, {
            'no_proxy': ""
        }):
            host = "10.0.0.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "foo.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "www.google.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "168.63.129.16"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "www.bar.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "10.0.0.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "10.0.1.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

        # When os.environ is empty - No global variables defined.
        with patch.dict(os.environ, {}):
            host = "10.0.0.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "foo.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "www.google.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "168.63.129.16"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "www.bar.com"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "10.0.0.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

            host = "10.0.1.1"
            self.assertTrue(use_proxy and not restutil.bypass_proxy(host))

    @patch("azurelinuxagent.common.future.httpclient.HTTPSConnection")
    @patch("azurelinuxagent.common.future.httpclient.HTTPConnection")
    def test_http_request_proxy_secure(self, HTTPConnection, HTTPSConnection): # pylint: disable=invalid-name
        mock_conn = \
            MagicMock(getresponse=\
                Mock(return_value=\
                    Mock(read=Mock(return_value="TheResults"))))

        HTTPSConnection.return_value = mock_conn

        resp = restutil._http_request("GET", "foo", "/bar", # pylint: disable=protected-access
                            proxy_host="foo.bar", proxy_port=23333,
                            secure=True)

        HTTPConnection.assert_not_called()
        HTTPSConnection.assert_has_calls([
            call("foo.bar", 23333, timeout=10)
        ])
        mock_conn.request.assert_has_calls([
            call(method="GET", url="https://foo:443/bar", body=None, headers={'User-Agent': HTTP_USER_AGENT, 'Connection': 'close'})
        ])
        self.assertEqual(1, mock_conn.getresponse.call_count)
        self.assertNotEqual(None, resp) 
        self.assertEqual("TheResults", resp.read()) 

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_with_retry(self, _http_request, sleep): # pylint: disable=unused-argument
        mock_http_resp = MagicMock()
        mock_http_resp.read = Mock(return_value="hehe")
        _http_request.return_value = mock_http_resp

        # Test http get
        resp = restutil.http_get("http://foo.bar")
        self.assertEqual("hehe", resp.read()) 

        # Test https get
        resp = restutil.http_get("https://foo.bar")
        self.assertEqual("hehe", resp.read()) 

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

    def test_it_should_have_http_request_retries_with_linear_delay(self):

        self.assertTrue(httpclient.BAD_GATEWAY in restutil.RETRY_CODES, "Ensure that the test params are correct")
        retry_delay_in_sec = 0.05

        for _ in range(3):
            mock_resp = Mock(return_value=MockHttpResponse(status=httpclient.BAD_GATEWAY))
            mock_conn = MagicMock(getresponse=mock_resp)
            max_retry = randint(5, 10)
            duration = None
            with patch("azurelinuxagent.common.future.httpclient.HTTPConnection", return_value=mock_conn):
                with self.assertRaises(HttpError):
                    start_time = datetime.utcnow()
                    restutil.http_get("http://foo.bar", retry_delay=retry_delay_in_sec, max_retry=max_retry)
                duration = datetime.utcnow() - start_time

            self.assertEqual(max_retry, mock_resp.call_count, "Did not Retry the required amount of times")
            upper_bound = timedelta(seconds=retry_delay_in_sec * (max_retry + 2))
            lower_bound = timedelta(seconds=retry_delay_in_sec * (max_retry - 2))
            self.assertTrue(upper_bound >= duration >= lower_bound,
                            "The total duration for request not in acceptable range. UB: {0}; LB: {1}; Actual: {2}".format(
                                upper_bound, lower_bound, duration))

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_with_constant_delay_when_throttled(self, _http_request, _sleep):
        # Ensure the code is a throttle code
        self.assertTrue(httpclient.SERVICE_UNAVAILABLE in restutil.THROTTLE_CODES)

        _http_request.side_effect = [
                Mock(status=httpclient.SERVICE_UNAVAILABLE)
                    for i in range(restutil.DEFAULT_RETRIES) # pylint: disable=unused-variable
            ] + [Mock(status=httpclient.OK)]

        restutil.http_get("https://foo.bar",
                            max_retry=restutil.DEFAULT_RETRIES+1)

        self.assertEqual(restutil.DEFAULT_RETRIES+1, _http_request.call_count)
        self.assertEqual(restutil.DEFAULT_RETRIES, _sleep.call_count)
        self.assertEqual(
            [call(1) for i in range(restutil.DEFAULT_RETRIES)],
            _sleep.call_args_list)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_retries_for_safe_minimum_number_when_throttled(self, _http_request, _sleep):
        # Ensure the code is a throttle code
        self.assertTrue(httpclient.SERVICE_UNAVAILABLE in restutil.THROTTLE_CODES)

        _http_request.side_effect = [
                Mock(status=httpclient.SERVICE_UNAVAILABLE)
                    for i in range(restutil.THROTTLE_RETRIES-1) # pylint: disable=unused-variable
            ] + [Mock(status=httpclient.OK)]

        restutil.http_get("https://foo.bar",
                            max_retry=1)

        self.assertEqual(restutil.THROTTLE_RETRIES, _http_request.call_count)
        self.assertEqual(restutil.THROTTLE_RETRIES-1, _sleep.call_count)
        self.assertEqual(
            [call(1) for i in range(restutil.THROTTLE_RETRIES-1)],
            _sleep.call_args_list)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_raises_for_resource_gone(self, _http_request, _sleep):
        _http_request.side_effect = [
            Mock(status=httpclient.GONE)
        ]

        self.assertRaises(ResourceGoneError, restutil.http_get, "https://foo.bar")
        self.assertEqual(1, _http_request.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_raises_for_invalid_container_configuration(self, _http_request, _sleep):
        def read():
            return b'{ "errorCode": "InvalidContainerConfiguration", "message": "Invalid request." }'

        _http_request.side_effect = [
            Mock(status=httpclient.BAD_REQUEST, reason='Bad Request', read=read)
        ]

        self.assertRaises(InvalidContainerError, restutil.http_get, "https://foo.bar")
        self.assertEqual(1, _http_request.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.common.utils.restutil._http_request")
    def test_http_request_raises_for_invalid_role_configuration(self, _http_request, _sleep):
        def read():
            return b'{ "errorCode": "RequestRoleConfigFileNotFound", "message": "Invalid request." }'

        _http_request.side_effect = [
            Mock(status=httpclient.GONE, reason='Resource Gone', read=read)
        ]

        self.assertRaises(ResourceGoneError, restutil.http_get, "https://foo.bar")
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
        ioerror.errno = 42

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
            for s in responses: # pylint: disable=invalid-name
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
            except HttpError as e: # pylint: disable=invalid-name
                self.assertTrue(result in ustr(e))


if __name__ == '__main__':
    unittest.main()
