# Microsoft Azure Linux Agent
#
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
import re
import threading
import time
import traceback
import socket
import struct

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.exception import HttpError, ResourceGoneError, InvalidContainerError
from azurelinuxagent.common.future import httpclient, urlparse, ustr
from azurelinuxagent.common.version import PY_VERSION_MAJOR, AGENT_NAME, GOAL_STATE_AGENT_VERSION

SECURE_WARNING_EMITTED = False

DEFAULT_RETRIES = 6
DELAY_IN_SECONDS = 1

THROTTLE_RETRIES = 25
THROTTLE_DELAY_IN_SECONDS = 1

REDACTED_TEXT = "<SAS_SIGNATURE>"
SAS_TOKEN_RETRIEVAL_REGEX = re.compile(r'^(https?://[a-zA-Z0-9.].*sig=)([a-zA-Z0-9%-]*)(.*)$')

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
    429,  # Request Rate Limit Exceeded
]

RESOURCE_GONE_CODES = [
    httpclient.GONE
]

OK_CODES = [
    httpclient.OK,
    httpclient.CREATED,
    httpclient.ACCEPTED
]

NOT_MODIFIED_CODES = [
    httpclient.NOT_MODIFIED
]

HOSTPLUGIN_UPSTREAM_FAILURE_CODES = [
    502
]

THROTTLE_CODES = [
    httpclient.FORBIDDEN,
    httpclient.SERVICE_UNAVAILABLE,
    429, # Request Rate Limit Exceeded
]

RETRY_EXCEPTIONS = [
    httpclient.NotConnected,
    httpclient.IncompleteRead,
    httpclient.ImproperConnectionState,
    httpclient.BadStatusLine
]

# http://www.gnu.org/software/wget/manual/html_node/Proxies.html
HTTP_PROXY_ENV = "http_proxy"
HTTPS_PROXY_ENV = "https_proxy"
NO_PROXY_ENV = "no_proxy"

HTTP_USER_AGENT = "{0}/{1}".format(AGENT_NAME, GOAL_STATE_AGENT_VERSION)
HTTP_USER_AGENT_HEALTH = "{0}+health".format(HTTP_USER_AGENT)
INVALID_CONTAINER_CONFIGURATION = "InvalidContainerConfiguration"
REQUEST_ROLE_CONFIG_FILE_NOT_FOUND = "RequestRoleConfigFileNotFound"

KNOWN_WIRESERVER_IP = '168.63.129.16'
HOST_PLUGIN_PORT = 32526


class IOErrorCounter(object):
    _lock = threading.RLock()
    _protocol_endpoint = KNOWN_WIRESERVER_IP
    _counts = {"hostplugin":0, "protocol":0, "other":0}

    @staticmethod
    def increment(host=None, port=None):
        with IOErrorCounter._lock:
            if host == IOErrorCounter._protocol_endpoint:
                if port == HOST_PLUGIN_PORT:
                    IOErrorCounter._counts["hostplugin"] += 1
                else:
                    IOErrorCounter._counts["protocol"] += 1
            else:
                IOErrorCounter._counts["other"] += 1

    @staticmethod
    def get_and_reset():
        with IOErrorCounter._lock:
            counts = IOErrorCounter._counts.copy()
            IOErrorCounter.reset()
            return counts

    @staticmethod
    def reset():
        with IOErrorCounter._lock:
            IOErrorCounter._counts = {"hostplugin":0, "protocol":0, "other":0}

    @staticmethod
    def set_protocol_endpoint(endpoint=KNOWN_WIRESERVER_IP):
        IOErrorCounter._protocol_endpoint = endpoint


def _compute_delay(retry_attempt=1, delay=DELAY_IN_SECONDS):
    fib = (1, 1)
    for _ in range(retry_attempt):
        fib = (fib[1], fib[0]+fib[1])
    return delay*fib[1]


def _is_retry_status(status, retry_codes=None):
    if retry_codes is None:
        retry_codes = RETRY_CODES
    return status in retry_codes


def _is_retry_exception(e):
    return len([x for x in RETRY_EXCEPTIONS if isinstance(e, x)]) > 0


def _is_throttle_status(status):
    return status in THROTTLE_CODES


def _parse_url(url):
    """
    Parse URL to get the components of the URL broken down to host, port
    :rtype: string, int, bool, string
    """
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


def is_valid_cidr(string_network):
    """
    Very simple check of the cidr format in no_proxy variable.
    :rtype: bool
    """
    if string_network.count('/') == 1:
        try:
            mask = int(string_network.split('/')[1])
        except ValueError:
            return False

        if mask < 1 or mask > 32:
            return False

        try:
            socket.inet_aton(string_network.split('/')[0])
        except socket.error:
            return False
    else:
        return False
    return True


def dotted_netmask(mask):
    """Converts mask from /xx format to xxx.xxx.xxx.xxx
    Example: if mask is 24 function returns 255.255.255.0
    :rtype: str
    """
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return socket.inet_ntoa(struct.pack('>I', bits))


def address_in_network(ip, net):
    """This function allows you to check if an IP belongs to a network subnet
    Example: returns True if ip = 192.168.1.1 and net = 192.168.1.0/24
             returns False if ip = 192.168.1.1 and net = 192.168.100.0/24
    :rtype: bool
    """
    ipaddr = struct.unpack('=L', socket.inet_aton(ip))[0]
    netaddr, bits = net.split('/')
    netmask = struct.unpack('=L', socket.inet_aton(dotted_netmask(int(bits))))[0]
    network = struct.unpack('=L', socket.inet_aton(netaddr))[0] & netmask
    return (ipaddr & netmask) == (network & netmask)


def is_ipv4_address(string_ip):
    """
    :rtype: bool
    """
    try:
        socket.inet_aton(string_ip)
    except socket.error:
        return False
    return True


def get_no_proxy():
    no_proxy = os.environ.get(NO_PROXY_ENV) or os.environ.get(NO_PROXY_ENV.upper())

    if no_proxy:
        no_proxy = [host for host in no_proxy.replace(' ', '').split(',') if host]

    # no_proxy in the proxies argument takes precedence
    return no_proxy


def bypass_proxy(host):
    no_proxy = get_no_proxy()

    if no_proxy:
        if is_ipv4_address(host):
            for proxy_ip in no_proxy:
                if is_valid_cidr(proxy_ip):
                    if address_in_network(host, proxy_ip):
                        return True
                elif host == proxy_ip:
                    # If no_proxy ip was defined in plain IP notation instead of cidr notation &
                    # matches the IP of the index
                    return True
        else:
            for proxy_domain in no_proxy:
                if host.lower().endswith(proxy_domain.lower()):
                    # The URL does match something in no_proxy, so we don't want
                    # to apply the proxies on this URL.
                    return True

    return False


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


def redact_sas_tokens_in_urls(url):
    return SAS_TOKEN_RETRIEVAL_REGEX.sub(r"\1" + REDACTED_TEXT + r"\3", url)


def _http_request(method, host, rel_uri, port=None, data=None, secure=False,
                  headers=None, proxy_host=None, proxy_port=None, redact_data=False):

    headers = {} if headers is None else headers
    headers['Connection'] = 'close'

    use_proxy = proxy_host is not None and proxy_port is not None

    if port is None:
        port = 443 if secure else 80

    if 'User-Agent' not in headers:
        headers['User-Agent'] = HTTP_USER_AGENT

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

    payload = data
    if redact_data:
        payload = "[REDACTED]"

    logger.verbose("HTTP connection [{0}] [{1}] [{2}] [{3}]",
                   method,
                   redact_sas_tokens_in_urls(url),
                   payload,
                   headers)

    conn.request(method=method, url=url, body=data, headers=headers)
    return conn.getresponse()


def http_request(method,
                 url, data, headers=None,
                 use_proxy=False,
                 max_retry=DEFAULT_RETRIES,
                 retry_codes=None,
                 retry_delay=DELAY_IN_SECONDS,
                 redact_data=False):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    global SECURE_WARNING_EMITTED  # pylint: disable=W0603

    host, port, secure, rel_uri = _parse_url(url)

    # Use the HTTP(S) proxy
    proxy_host, proxy_port = (None, None)
    if use_proxy and not bypass_proxy(host):
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
    delay = 0
    was_throttled = False

    while attempt < max_retry:
        if attempt > 0:
            # Compute the request delay
            # -- Use a fixed delay if the server ever rate-throttles the request
            #    (with a safe, minimum number of retry attempts)
            # -- Otherwise, compute a delay that is the product of the next
            #    item in the Fibonacci series and the initial delay value
            delay = THROTTLE_DELAY_IN_SECONDS \
                        if was_throttled \
                        else _compute_delay(retry_attempt=attempt,
                                            delay=retry_delay)

            logger.verbose("[HTTP Retry] "
                        "Attempt {0} of {1} will delay {2} seconds: {3}", 
                        attempt+1, 
                        max_retry, 
                        delay, 
                        msg) 

            time.sleep(delay)

        attempt += 1

        try:
            resp = _http_request(method,
                                 host,
                                 rel_uri,
                                 port=port,
                                 data=data,
                                 secure=secure,
                                 headers=headers,
                                 proxy_host=proxy_host,
                                 proxy_port=proxy_port,
                                 redact_data=redact_data)
            logger.verbose("[HTTP Response] Status Code {0}", resp.status)

            if request_failed(resp):
                if _is_retry_status(resp.status, retry_codes=retry_codes):
                    msg = '[HTTP Retry] {0} {1} -- Status Code {2}'.format(method, url, resp.status)
                    # Note if throttled and ensure a safe, minimum number of
                    # retry attempts
                    if _is_throttle_status(resp.status):
                        was_throttled = True
                        max_retry = max(max_retry, THROTTLE_RETRIES)
                    continue

            # If we got a 410 (resource gone) for any reason, raise an exception. The caller will handle it by
            # forcing a goal state refresh and retrying the call.
            if resp.status in RESOURCE_GONE_CODES:
                response_error = read_response_error(resp)
                raise ResourceGoneError(response_error)

            # If we got a 400 (bad request) because the container id is invalid, it could indicate a stale goal
            # state. The caller will handle this exception by forcing a goal state refresh and retrying the call.
            if resp.status == httpclient.BAD_REQUEST:
                response_error = read_response_error(resp)
                if INVALID_CONTAINER_CONFIGURATION in response_error:
                    raise InvalidContainerError(response_error)

            return resp

        except httpclient.HTTPException as e:
            clean_url = redact_sas_tokens_in_urls(url)
            msg = '[HTTP Failed] {0} {1} -- HttpException {2}'.format(method, clean_url, e)
            if _is_retry_exception(e):
                continue
            break

        except IOError as e:
            IOErrorCounter.increment(host=host, port=port)
            clean_url = redact_sas_tokens_in_urls(url)
            msg = '[HTTP Failed] {0} {1} -- IOError {2}'.format(method, clean_url, e)
            continue

    raise HttpError("{0} -- {1} attempts made".format(msg, attempt))


def http_get(url,
             headers=None,
             use_proxy=False,
             max_retry=DEFAULT_RETRIES,
             retry_codes=None,
             retry_delay=DELAY_IN_SECONDS):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    return http_request("GET",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_head(url,
              headers=None,
              use_proxy=False,
              max_retry=DEFAULT_RETRIES,
              retry_codes=None,
              retry_delay=DELAY_IN_SECONDS):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    return http_request("HEAD",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_post(url,
              data,
              headers=None,
              use_proxy=False,
              max_retry=DEFAULT_RETRIES,
              retry_codes=None,
              retry_delay=DELAY_IN_SECONDS):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    return http_request("POST",
                        url, data, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def http_put(url,
             data,
             headers=None,
             use_proxy=False,
             max_retry=DEFAULT_RETRIES,
             retry_codes=None,
             retry_delay=DELAY_IN_SECONDS,
             redact_data=False):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    return http_request("PUT",
                        url, data, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay,
                        redact_data=redact_data)


def http_delete(url,
                headers=None,
                use_proxy=False,
                max_retry=DEFAULT_RETRIES,
                retry_codes=None,
                retry_delay=DELAY_IN_SECONDS):

    if retry_codes is None:
        retry_codes = RETRY_CODES
    return http_request("DELETE",
                        url, None, headers=headers,
                        use_proxy=use_proxy,
                        max_retry=max_retry,
                        retry_codes=retry_codes,
                        retry_delay=retry_delay)


def request_failed(resp, ok_codes=None):
    if ok_codes is None:
        ok_codes = OK_CODES
    return not request_succeeded(resp, ok_codes=ok_codes)


def request_succeeded(resp, ok_codes=None):
    if ok_codes is None:
        ok_codes = OK_CODES
    return resp is not None and resp.status in ok_codes


def request_not_modified(resp):
    return resp is not None and resp.status in NOT_MODIFIED_CODES


def request_failed_at_hostplugin(resp, upstream_failure_codes=None):
    """
    Host plugin will return 502 for any upstream issue, so a failure is any 5xx except 502
    """
    if upstream_failure_codes is None:
        upstream_failure_codes = HOSTPLUGIN_UPSTREAM_FAILURE_CODES
    return resp is not None and resp.status >= 500 and resp.status not in upstream_failure_codes


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
