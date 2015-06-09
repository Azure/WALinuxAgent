# Windows Azure Linux Agent
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

import platform
import os
import subprocess
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
import httplib
import time
from urlparse import urlparse

"""
REST api util functions
"""
__RetryWaitingInterval=10

class HttpError(Exception):
    pass

def _ParseUrl(url):
    o = urlparse(url)
    relativeUrl = o.path
    if o.fragment:
        relativeUrl = "{0}#{1}".format(relativeUrl, o.fragment)
    if o.query:
        relativeUrl = "{0}?{1}".format(relativeUrl, o.query)
    secure = False
    if o.scheme.lower() == "https":
        secure = True
    return o.hostname, o.port, secure, relativeUrl

def GetHttpProxy():
    """
    Get http_proxy and https_proxy from environment variables.
    Username and password is not supported now.
    """
    host = conf.Get("HttpProxy.Host", None)
    port = conf.Get("HttpProxy.Port", None)
    return (host, port) 

def _HttpRequest(method, host, relativeUrl, port=None, data=None, secure=False, 
                 headers=None, proxyHost=None, proxyPort=None):
    url, conn = None, None
    if secure:
        port = 443 if port is None else port
        if proxyHost is not None and proxyPort is not None:
            conn = httplib.HTTPSConnection(proxyHost, proxyPort)
            conn.set_tunnel(host, port)
            #If proxy is used, full url is needed.
            url = "https://{0}:{1}{2}".format(host, port, relativeUrl)
        else:
            conn = httplib.HTTPSConnection(host, port)
            url = relativeUrl
    else:
        port = 80 if port is None else port
        if proxyHost is not None and proxyPort is not None:
            conn = httplib.HTTPConnection(proxyHost, proxyPort)
            #If proxy is used, full url is needed.
            url = "http://{0}:{1}{2}".format(host, port, relativeUrl)
        else:
            conn = httplib.HTTPConnection(host, port)
            url = relativeUrl
    if headers == None:
        conn.request(method, url, data)
    else:
        conn.request(method, url, data, headers)
    resp = conn.getresponse()
    return resp

def HttpRequest(method, url, data, headers=None, maxRetry=3, chkProxy=False):
    """
    Sending http request to server
    On error, sleep 10 and retry maxRetry times.
    """
    logger.Verbose("HTTP Req: {0} {1}", method, url)
    logger.Verbose("    Data={0}", data)
    logger.Verbose("    Header={0}", headers)
    host, port, secure, relativeUrl = _ParseUrl(url)

    #Check proxy
    proxyHost, proxyPort = (None, None)
    if chkProxy:
        proxyHost, proxyPort = GetHttpProxy()

    #If httplib module is not built with ssl support. Fallback to http
    if secure and not hasattr(httplib, "HTTPSConnection"):
        logger.Warn("httplib is not built with ssl support")
        secure = False
    
    #If httplib module doesn't support https tunnelling. Fallback to http
    if secure and \
            proxyHost is not None and \
            proxyPort is not None and \
            not hasattr(httplib.HTTPSConnection, "set_tunnel"):
        logger.Warn("httplib doesn't support https tunnelling(new in python 2.7)")
        secure = False

    for retry in range(0, maxRetry):
        try:
            resp = _HttpRequest(method, host, relativeUrl, port, data, 
                                secure, headers, proxyHost, proxyPort)
            logger.Verbose("HTTP Resp: Status={0}", resp.status)
            logger.Verbose("    Header={0}", resp.getheaders())
            return resp
        except httplib.HTTPException as e:
            logger.Warn('HTTPException {0}, args:{1}', e, repr(e.args))
        except IOError as e:
            logger.Warn('Socket IOError {0}, args:{1}', e, repr(e.args)) 

        if retry < maxRetry - 1:
            logger.Info("Retry={0}, {1} {2}", retry, method, url)
            time.sleep(__RetryWaitingInterval)

    raise HttpError("HTTP Err: {0} {1}".format(method, url))

def HttpGet(url, headers=None, maxRetry=3, chkProxy=False):
    return HttpRequest("GET", url, None, headers, maxRetry, chkProxy)
    
def HttpHead(url, headers=None, maxRetry=3, chkProxy=False):
    return HttpRequest("HEAD", url, None, headers, maxRetry, chkProxy)
    
def HttpPost(url, data, headers=None, maxRetry=3, chkProxy=False):
    return HttpRequest("POST", url, data, headers, maxRetry, chkProxy)

def HttpPut(url, data, headers=None, maxRetry=3, chkProxy=False):
    return HttpRequest("PUT", url, data, headers, maxRetry, chkProxy)

def HttpDelete(url, headers=None, maxRetry=3, chkProxy=False):
    return HttpRequest("DELETE", url, None, headers, maxRetry, chkProxy)

#End REST api util functions
