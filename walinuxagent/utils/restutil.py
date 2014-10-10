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
import walinuxagent.logger as logger
import httplib
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

    return o.netloc, action

def _HttpRequest(method, host, action, data=None, headers=None):
    resp = None;
    try:
        httpConnection = httplib.HTTPConnection(host)
        if headers == None:
            httpConnection.request(method, action, data)
        else:
            httpConnection.request(method, action, data, headers)
        resp = httpConnection.getresponse()
    except httplib.HTTPException, e:
        logger.Error('HTTPException {0}, args:{1}', e, repr(e.args))
    except IOError, e:
        logger.Error('Socket IOError {0}, args:{1}', e, repr(e.args)) 
    return resp

def HttpRequest(method, url, data, headers=None, maxRetry=0):
    """
    Sending http request to server
    On error, sleep 10 and maxRetry times.
    Return the output buffer or None.
    """
    logger.Verbose("{0} {1}", method, url)
    host, action = _ParseUrl(url)
    resp = _HttpRequest(method, host, action, data, headers)
    for retry in range(0, maxRetry):
        if resp and resp.status == httplib.OK:
            break;
        else:
            logger.Error("Retry={0}, Status={1}, {2} {3}{4}", retry, 
                         resp.status, method, host, action)
        time.sleep(__RetryWaitingInterval)
        resp = _HttpRequest(method, host, action, data, headers)

    if resp and (resp.status == httplib.OK or resp.status == httplib.ACCEPTED):
        return resp.read()
    else:
        return None

def HttpGet(url, headers=None, maxRetry=0):
    return HttpRequest("GET", url, None, headers, maxRetry)
    
def HttpPost(url, data, headers=None, maxRetry=0):
    return HttpRequest("POST", url, data, headers, maxRetry)

def HttpPut(url, data, headers=None, maxRetry=0):
    return HttpRequest("PUT", url, data, headers, maxRetry)

def HttpDelete(url, data, headers=None, maxRetry=0):
    return HttpRequest("DELETE", url, data, headers, maxRetry)
   
def HttpPutBlockBlob(url, data, maxRetry):
    headers = {
        "x-ms-blob-type" : "BlockBlob", 
        "x-ms-date" : time.strftime("%Y-%M-%dT%H:%M:%SZ", time.gmtime()),
        "Content-Length": str(len(data))
    }
    return HttpPut(url, data, headers, maxRetry)

#End REST api util functions
