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
import platform
import os
import subprocess
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import httpclient, urlparse

"""
REST api util functions
"""

RETRY_WAITING_INTERVAL = 10

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
    return (host, port)

def _http_request(method, host, rel_uri, port=None, data=None, secure=False,
                 headers=None, proxy_host=None, proxy_port=None):
    url, conn = None, None
    if secure:
        port = 443 if port is None else port
        if proxy_host is not None and proxy_port is not None:
            conn = httpclient.HTTPSConnection(proxy_host, proxy_port, timeout=10)
            conn.set_tunnel(host, port)
            #If proxy is used, full url is needed.
            url = "https://{0}:{1}{2}".format(host, port, rel_uri)
        else:
            conn = httpclient.HTTPSConnection(host, port, timeout=10)
            url = rel_uri
    else:
        port = 80 if port is None else port
        if proxy_host is not None and proxy_port is not None:
            conn = httpclient.HTTPConnection(proxy_host, proxy_port, timeout=10)
            #If proxy is used, full url is needed.
            url = "http://{0}:{1}{2}".format(host, port, rel_uri)
        else:
            conn = httpclient.HTTPConnection(host, port, timeout=10)
            url = rel_uri
    if headers == None:
        conn.request(method, url, data)
    else:
        conn.request(method, url, data, headers)
    resp = conn.getresponse()
    return resp

def http_request(method, url, data, headers=None, max_retry=3, chk_proxy=False):
    """
    Sending http request to server
    On error, sleep 10 and retry max_retry times.
    """
    logger.verb("HTTP Req: {0} {1}", method, url)
    logger.verb("    Data={0}", data)
    logger.verb("    Header={0}", headers)
    host, port, secure, rel_uri = _parse_url(url)

    #Check proxy
    proxy_host, proxy_port = (None, None)
    if chk_proxy:
        proxy_host, proxy_port = get_http_proxy()

    #If httplib module is not built with ssl support. Fallback to http
    if secure and not hasattr(httpclient, "HTTPSConnection"):
        logger.warn("httplib is not built with ssl support")
        secure = False

    #If httplib module doesn't support https tunnelling. Fallback to http
    if secure and \
            proxy_host is not None and \
            proxy_port is not None and \
            not hasattr(httpclient.HTTPSConnection, "set_tunnel"):
        logger.warn("httplib doesn't support https tunnelling(new in python 2.7)")
        secure = False

    for retry in range(0, max_retry):
        try:
            resp = _http_request(method, host, rel_uri, port=port, data=data, 
                                 secure=secure, headers=headers, 
                                 proxy_host=proxy_host, proxy_port=proxy_port)
            logger.verb("HTTP Resp: Status={0}", resp.status)
            logger.verb("    Header={0}", resp.getheaders())
            return resp
        except httpclient.HTTPException as e:
            logger.warn('HTTPException {0}, args:{1}', e, repr(e.args))
        except IOError as e:
            logger.warn('Socket IOError {0}, args:{1}', e, repr(e.args))

        if retry < max_retry - 1:
            logger.info("Retry={0}, {1} {2}", retry, method, url)
            time.sleep(RETRY_WAITING_INTERVAL)
    
    if url is not None and len(url) > 100:
        url_log = url[0: 100] #In case the url is too long
    else:
        url_log = url
    raise HttpError("HTTP Err: {0} {1}".format(method, url_log))

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

#End REST api util functions
