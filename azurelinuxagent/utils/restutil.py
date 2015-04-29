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
import httplib
import time
from urlparse import urlparse

"""
REST api util functions
"""
__RetryWaitingInterval=10


def _ParseUrl(url):
    o = urlparse(url)
    action = o.path
    if o.query:
        action = "{0}?{1}".format(action, o.query)
    if o.fragment:
        action = "{0}#{1}".format(action, o.fragment)
    secure = False
    if o.scheme.lower() == "https":
        secure = True
    return o.netloc, action, secure

def _HttpRequest(method, host, action, data=None, secure=False, headers=None):
    httpConnection = None

    #If httplib module is not built with ssl support. Failback to http
    if secure and hasattr(httplib, "HTTPSConnection"):
        httpConnection = httplib.HTTPSConnection(host)
    else:
        httpConnection = httplib.HTTPConnection(host)
    if headers == None:
        httpConnection.request(method, action, data)
    else:
        httpConnection.request(method, action, data, headers)
    resp = httpConnection.getresponse()
    if resp is None:
        raise ValueError("Http response is None")
    return resp

def HttpRequest(method, url, data, headers=None,  maxRetry=3):
    """
    Sending http request to server
    On error, sleep 10 and retry maxRetry times.
    """
    logger.Verbose("HTTP Req: {0} {1}", method, url)
    logger.Verbose("    Data={0}", data)
    logger.Verbose("    Header={0}", headers)
    host, action, secure = _ParseUrl(url)

    for retry in range(0, maxRetry):
        try:
            resp = _HttpRequest(method, host, action, data, secure, headers)
            logger.Verbose("HTTP Resp: Status={0}", resp.status)
            logger.Verbose("    Header={0}", resp.getheaders())
            logger.Verbose("    Body={0}", resp.read())
            return resp
        except httplib.HTTPException, e:
            logger.Warn('HTTPException {0}, args:{1}', e, repr(e.args))
        except IOError, e:
            logger.Warn('Socket IOError {0}, args:{1}', e, repr(e.args)) 

        logger.Warn("Retry={0}, {1} {2}", retry, method, url)
        time.sleep(__RetryWaitingInterval)
    raise e 

def HttpGet(url, headers=None, maxRetry=3):
    return HttpRequest("GET", url, None, headers, maxRetry)
    
def HttpPost(url, data, headers=None, maxRetry=3):
    return HttpRequest("POST", url, data, headers, maxRetry)

def HttpPut(url, data, headers=None, maxRetry=3):
    return HttpRequest("PUT", url, data, headers, maxRetry)

def HttpDelete(url, headers=None, maxRetry=3):
    return HttpRequest("DELETE", url, None, headers, maxRetry)
   
def HttpPutBlockBlob(url, data, maxRetry=3):
    headers = {
        "x-ms-blob-type" : "BlockBlob", 
        "x-ms-date" : time.strftime("%Y-%M-%dT%H:%M:%SZ", time.gmtime()),
        "Content-Length": str(len(data))
    }
    return HttpPut(url, data, headers, maxRetry)

#End REST api util functions
