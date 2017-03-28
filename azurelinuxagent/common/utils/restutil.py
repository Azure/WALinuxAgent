# Microsoft Azure Linux Agent
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
#
# Requires Python 2.4+ and Openssl 1.0+
#

import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import httpclient, urlparse

"""
REST api util functions
"""

RETRY_WAITING_INTERVAL = 3
secure_warning = True


def _parse_url(url):
    o = urlparse(url)
    rel_uri = o.path
    if o.fragment:
        rel_uri = "{0}#{1}".format(rel_uri, o.fragment)
    if o.query:
        rel_uri = "{0}?{1}".format(rel_uri, o.query)
    secure = False
    if o.scheme.lower() == "https":
        secure = True
    return o.hostname, o.port, secure, rel_uri


def get_http_proxy():
    """
    Get http_proxy and https_proxy from environment variables.
    Username and password is not supported now.
    """
    host = conf.get_httpproxy_host()
    port = conf.get_httpproxy_port()
    return host, port


def _http_request(method, host, rel_uri, port=None, data=None, secure=False,
                  headers=None, proxy_host=None, proxy_port=None):
    url, conn = None, None
    if secure:
        port = 443 if port is None else port
        if proxy_host is not None and proxy_port is not None:
            conn = httpclient.HTTPSConnection(proxy_host,
                                              proxy_port,
                                              timeout=10)
            conn.set_tunnel(host, port)
            # If proxy is used, full url is needed.
            url = "https://{0}:{1}{2}".format(host, port, rel_uri)
        else:
            conn = httpclient.HTTPSConnection(host,
                                              port,
                                              timeout=10)
            url = rel_uri
    else:
        port = 80 if port is None else port
        if proxy_host is not None and proxy_port is not None:
            conn = httpclient.HTTPConnection(proxy_host,
                                             proxy_port,
                                             timeout=10)
            # If proxy is used, full url is needed.
            url = "http://{0}:{1}{2}".format(host, port, rel_uri)
        else:
            conn = httpclient.HTTPConnection(host,
                                             port,
                                             timeout=10)
            url = rel_uri

    logger.verbose("HTTP connection [{0}] [{1}] [{2}] [{3}]",
                   method,
                   url,
                   data,
                   headers)

    headers = {} if headers is None else headers
    conn.request(method=method, url=url, body=data, headers=headers)
    resp = conn.getresponse()
    return resp


def http_request(method, url, data, headers=None, max_retry=3,
                 chk_proxy=False):
    """
    Sending http request to server
    On error, sleep 10 and retry max_retry times.
    """
    host, port, secure, rel_uri = _parse_url(url)
    global secure_warning

    # Check proxy
    proxy_host, proxy_port = (None, None)
    if chk_proxy:
        proxy_host, proxy_port = get_http_proxy()

    # If httplib module is not built with ssl support. Fallback to http
    if secure and not hasattr(httpclient, "HTTPSConnection"):
        secure = False
        if secure_warning:
            logger.warn("httplib is not built with ssl support")
            secure_warning = False

    # If httplib module doesn't support https tunnelling. Fallback to http
    if secure and proxy_host is not None and proxy_port is not None \
            and not hasattr(httpclient.HTTPSConnection, "set_tunnel"):
        secure = False
        if secure_warning:
            logger.warn("httplib does not support https tunnelling "
                        "(new in python 2.7)")
            secure_warning = False

    if proxy_host or proxy_port:
        logger.verbose("HTTP proxy: [{0}:{1}]", proxy_host, proxy_port)

    retry_msg = ''
    log_msg = "HTTP {0}".format(method)
    for retry in range(0, max_retry):
        retry_interval = RETRY_WAITING_INTERVAL
        try:
            resp = _http_request(method,
                                 host,
                                 rel_uri,
                                 port=port,
                                 data=data,
                                 secure=secure,
                                 headers=headers,
                                 proxy_host=proxy_host,
                                 proxy_port=proxy_port)
            logger.verbose("HTTP response status: [{0}]", resp.status)
            return resp
        except httpclient.HTTPException as e:
            retry_msg = 'HTTP exception: {0} {1}'.format(log_msg, e)
            retry_interval = 5
        except IOError as e:
            retry_msg = 'IO error: {0} {1}'.format(log_msg, e)
            # error 101: network unreachable; when the adapter resets we may
            # see this transient error for a short time, retry once.
            if e.errno == 101:
                retry_interval = RETRY_WAITING_INTERVAL
                max_retry = 1
            else:
                retry_interval = 0
                max_retry = 0

        if retry < max_retry:
            logger.info("Retry [{0}/{1} - {3}]",
                        retry+1,
                        max_retry,
                        retry_interval,
                        retry_msg)
            time.sleep(retry_interval)

    raise HttpError("{0} failed".format(log_msg))


def http_get(url, headers=None, max_retry=3, chk_proxy=False):
    return http_request("GET", url, data=None, headers=headers,
                        max_retry=max_retry, chk_proxy=chk_proxy)


def http_head(url, headers=None, max_retry=3, chk_proxy=False):
    return http_request("HEAD", url, None, headers=headers,
                        max_retry=max_retry, chk_proxy=chk_proxy)


def http_post(url, data, headers=None, max_retry=3, chk_proxy=False):
    return http_request("POST", url, data, headers=headers,
                        max_retry=max_retry, chk_proxy=chk_proxy)


def http_put(url, data, headers=None, max_retry=3, chk_proxy=False):
    return http_request("PUT", url, data, headers=headers,
                        max_retry=max_retry, chk_proxy=chk_proxy)


def http_delete(url, headers=None, max_retry=3, chk_proxy=False):
    return http_request("DELETE", url, None, headers=headers,
                        max_retry=max_retry, chk_proxy=chk_proxy)

# End REST api util functions
