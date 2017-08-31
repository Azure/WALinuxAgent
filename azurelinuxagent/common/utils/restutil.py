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

import os
import time
import traceback

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import httpclient, urlparse, ustr
from azurelinuxagent.common.version import PY_VERSION_MAJOR


SECURE_WARNING_EMITTED = False

DEFAULT_RETRIES = 3

SHORT_DELAY_IN_SECONDS = 5
LONG_DELAY_IN_SECONDS = 15

RETRY_CODES = [
    httpclient.RESET_CONTENT,
    httpclient.PARTIAL_CONTENT,
    httpclient.FORBIDDEN,
    httpclient.INTERNAL_SERVER_ERROR,
    httpclient.NOT_IMPLEMENTED,
    httpclient.BAD_GATEWAY,
    httpclient.SERVICE_UNAVAILABLE,
    httpclient.GATEWAY_TIMEOUT,
    httpclient.INSUFFICIENT_STORAGE,
    429, # Request Rate Limit Exceeded
]

RESOURCE_GONE_CODES = [
    httpclient.BAD_REQUEST,
    httpclient.GONE
]

OK_CODES = [
    httpclient.OK,
    httpclient.CREATED,
    httpclient.ACCEPTED
]

THROTTLE_CODES = [
    httpclient.FORBIDDEN,
    httpclient.SERVICE_UNAVAILABLE
]

RETRY_EXCEPTIONS = [
    httpclient.NotConnected,
    httpclient.IncompleteRead,
    httpclient.ImproperConnectionState,
    httpclient.BadStatusLine
]

HTTP_PROXY_ENV = "http_proxy"
HTTPS_PROXY_ENV = "https_proxy"


def _is_retry_status(status, retry_codes=RETRY_CODES):
    return status in retry_codes

def _is_retry_exception(e):
    return len([x for x in RETRY_EXCEPTIONS if isinstance(e, x)]) > 0

def _is_throttle_status(status):
    return status in THROTTLE_CODES

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


def _get_http_proxy(secure=False):
    # Prefer the configuration settings over environment variables
    host = conf.get_httpproxy_host()
    port = None

    if not host is None:
        port = conf.get_httpproxy_port()

    else:
        http_proxy_env = HTTPS_PROXY_ENV if secure else HTTP_PROXY_ENV
        http_proxy_url = None
        for v in [http_proxy_env, http_proxy_env.upper()]:
            if v in os.environ:
                http_proxy_url = os.environ[v]
                break

        if not http_proxy_url is None:
            host, port, _, _ = _parse_url(http_proxy_url)

    return host, port


def _http_request(method, host, rel_uri, port=None, data=None, secure=False,
                  headers=None, proxy_host=None, proxy_port=None):

    headers = {} if headers is None else headers
    use_proxy = proxy_host is not None and proxy_port is not None

    if port is None:
        port = 443 if secure else 80

    if use_proxy:
        conn_host, conn_port = proxy_host, proxy_port
        scheme = "https" if secure else "http"
        url = "{0}://{1}:{2}{3}".format(scheme, host, port, rel_uri)

    else:
        conn_host, conn_port = host, port
        url = rel_uri

    if secure:
        conn = httpclient.HTTPSConnection(conn_host,
                                        conn_port,
                                        timeout=10)
        if use_proxy:
            conn.set_tunnel(host, port)

    else:
        conn = httpclient.HTTPConnection(conn_host,
                                        conn_port,
                                        timeout=10)

    logger.verbose("HTTP connection [{0}] [{1}] [{2}] [{3}]",
                   method,
                   url,
                   data,
                   headers)

    conn.request(method=method, url=url, body=data, headers=headers)
    return conn.getresponse()


def http_request(method,
                url, data, headers=None,
                use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):

    global SECURE_WARNING_EMITTED

    host, port, secure, rel_uri = _parse_url(url)

    # Use the HTTP(S) proxy
    proxy_host, proxy_port = (None, None)
    if use_proxy:
        proxy_host, proxy_port = _get_http_proxy(secure=secure)

        if proxy_host or proxy_port:
            logger.verbose("HTTP proxy: [{0}:{1}]", proxy_host, proxy_port)

    # If httplib module is not built with ssl support,
    # fallback to HTTP if allowed
    if secure and not hasattr(httpclient, "HTTPSConnection"):
        if not conf.get_allow_http():
            raise HttpError("HTTPS is unavailable and required")

        secure = False
        if not SECURE_WARNING_EMITTED:
            logger.warn("Python does not include SSL support")
            SECURE_WARNING_EMITTED = True

    # If httplib module doesn't support HTTPS tunnelling,
    # fallback to HTTP if allowed
    if secure and \
        proxy_host is not None and \
        proxy_port is not None \
        and not hasattr(httpclient.HTTPSConnection, "set_tunnel"):

        if not conf.get_allow_http():
            raise HttpError("HTTPS tunnelling is unavailable and required")

        secure = False
        if not SECURE_WARNING_EMITTED:
            logger.warn("Python does not support HTTPS tunnelling")
            SECURE_WARNING_EMITTED = True

    msg = ''
    attempt = 0
    delay = retry_delay

    while attempt < max_retry:
        if attempt > 0:
            logger.info("[HTTP Retry] Attempt {0} of {1}: {2}",
                        attempt+1,
                        max_retry,
                        msg)
            time.sleep(delay)

        attempt += 1
        delay = retry_delay

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
            logger.verbose("[HTTP Response] Status Code {0}", resp.status)

            if request_failed(resp):
                if _is_retry_status(resp.status, retry_codes=retry_codes):
                    msg = '[HTTP Retry] HTTP {0} Status Code {1}'.format(
                        method, resp.status)
                    if _is_throttle_status(resp.status):
                        delay = LONG_DELAY_IN_SECONDS
                        logger.info("[HTTP Delay] Delay {0} seconds for " \
                                    "Status Code {1}".format(
                                        delay, resp.status))
                    continue

            if resp.status in RESOURCE_GONE_CODES:
                raise ResourceGoneError()

            return resp

        except httpclient.HTTPException as e:
            msg = '[HTTP Failed] HTTP {0} HttpException {1}'.format(method, e)
            if _is_retry_exception(e):
                continue
            break

        except IOError as e:
            msg = '[HTTP Failed] HTTP {0} IOError {1}'.format(method, e)
            continue

    raise HttpError(msg)


def http_get(url, headers=None, use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):
    return http_request("GET",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_head(url, headers=None, use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):
    return http_request("HEAD",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_post(url, data, headers=None, use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):
    return http_request("POST",
                        url, data, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_put(url, data, headers=None, use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):
    return http_request("PUT",
                        url, data, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_delete(url, headers=None, use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=RETRY_CODES,
                retry_delay=SHORT_DELAY_IN_SECONDS):
    return http_request("DELETE",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)

def request_failed(resp, ok_codes=OK_CODES):
    return not request_succeeded(resp, ok_codes=ok_codes)

def request_succeeded(resp, ok_codes=OK_CODES):
    return resp is not None and resp.status in ok_codes

def read_response_error(resp):
    result = ''
    if resp is not None:
        try:
            result = "[HTTP Failed] [{0}: {1}] {2}".format(
                        resp.status,
                        resp.reason,
                        resp.read())

            # this result string is passed upstream to several methods
            # which do a raise HttpError() or a format() of some kind;
            # as a result it cannot have any unicode characters
            if PY_VERSION_MAJOR < 3:
                result = ustr(result, encoding='ascii', errors='ignore')
            else:
                result = result\
                    .encode(encoding='ascii', errors='ignore')\
                    .decode(encoding='ascii', errors='ignore')

            result = textutil.replace_non_ascii(result)

        except Exception:
            logger.warn(traceback.format_exc())
    return result
