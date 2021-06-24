# Copyright 2020 Microsoft Corporation
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
import contextlib
import re
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils import restutil
from tests.tools import patch
from tests.protocol import mockwiredata

# regex used to determine whether to use the mock wireserver data
_USE_MOCK_WIRE_DATA_RE = re.compile(
    r'https?://(mock-goal-state|{0}).*'.format(restutil.KNOWN_WIRESERVER_IP.replace(r'.', r'\.')), re.IGNORECASE)


@contextlib.contextmanager
def mock_wire_protocol(mock_wire_data_file, http_get_handler=None, http_post_handler=None, http_put_handler=None, fail_on_unknown_request=True):
    """
    Creates a WireProtocol object that handles requests to the WireServer and the Host GA Plugin (i.e requests on the WireServer endpoint), plus
    some requests to storage (requests on the fake server 'mock-goal-state').

    The data returned by those requests is read from the files specified by 'mock_wire_data_file' (which must follow the structure of the data
    files defined in tests/protocol/mockwiredata.py).

    The caller can also provide handler functions for specific HTTP methods using the http_*_handler arguments. The return value of the handler
    function is interpreted similarly to the "return_value" argument of patch(): if it is an exception the exception is raised or, if it is
    any object other than None, the value is returned by the mock. If the handler function returns None the call is handled using the mock
    wireserver data or passed to the original to restutil.http_request.

    The returned protocol object maintains a list of "tracked" urls. When a handler function returns a value than is not None the url for the
    request is automatically added to the tracked list. The handler function can add other items to this list using the track_url() method on
    the mock.

    The return value of this function is an instance of WireProtocol augmented with these properties/methods:

        * mock_wire_data - the WireProtocolData constructed from the mock_wire_data_file parameter.
        * start() - starts the patchers for http_request and CryptUtil
        * stop() - stops the patchers
        * track_url(url) - adds the given item to the list of tracked urls.
        * get_tracked_urls() - returns the list of tracked urls.

    NOTE: This function patches common.utils.restutil.http_request and common.protocol.wire.CryptUtil; you need to be aware of this if your
          tests patch those methods or others in the call stack (e.g. restutil.get, resutil._http_request, etc)

    """
    tracked_urls = []

    # use a helper function to keep the HTTP handlers (they need to be modified by set_http_handlers() and
    # Python 2.* does not support nonlocal declarations)
    def http_handlers(get, post, put):
        http_handlers.get = get
        http_handlers.post = post
        http_handlers.put = put
        del tracked_urls[:]
    http_handlers(get=http_get_handler, post=http_post_handler, put=http_put_handler)

    #
    # function used to patch restutil.http_request
    #
    original_http_request = restutil.http_request

    def http_request(method, url, data, **kwargs):
        # if there is a handler for the request, use it
        handler = None
        if method == 'GET':
            handler = http_handlers.get
        elif method == 'POST':
            handler = http_handlers.post
        elif method == 'PUT':
            handler = http_handlers.put

        if handler is not None:
            if method == 'GET':
                return_value = handler(url, **kwargs)
            else:
                return_value = handler(url, data, **kwargs)
            if return_value is not None:
                tracked_urls.append(url)
                if isinstance(return_value, Exception):
                    raise return_value
                return return_value

        # if the request was not handled try to use the mock wireserver data
        if _USE_MOCK_WIRE_DATA_RE.match(url) is not None:
            if method == 'GET':
                return protocol.mock_wire_data.mock_http_get(url, **kwargs)
            if method == 'POST':
                return protocol.mock_wire_data.mock_http_post(url, data, **kwargs)
            if method == 'PUT':
                return protocol.mock_wire_data.mock_http_put(url, data, **kwargs)

        # the request was not handled; fail or call the original resutil.http_request
        if fail_on_unknown_request:
            raise ValueError('Unknown HTTP request: {0} [{1}]'.format(url, method))
        return original_http_request(method, url, data, **kwargs)

    #
    # functions to start/stop the mocks
    #
    def start():
        patched = patch("azurelinuxagent.common.utils.restutil.http_request", side_effect=http_request)
        patched.start()
        start.http_request_patch = patched

        patched = patch("azurelinuxagent.common.protocol.wire.CryptUtil", side_effect=protocol.mock_wire_data.mock_crypt_util)
        patched.start()
        start.crypt_util_patch = patched
    start.http_request_patch = None
    start.crypt_util_patch = None

    def stop():
        if start.crypt_util_patch is not None:
            start.crypt_util_patch.stop()
        if start.http_request_patch is not None:
            start.http_request_patch.stop()

    #
    # create the protocol object
    #
    protocol = WireProtocol(restutil.KNOWN_WIRESERVER_IP)
    protocol.mock_wire_data = mockwiredata.WireProtocolData(mock_wire_data_file)
    protocol.start = start
    protocol.stop = stop
    protocol.track_url = lambda url: tracked_urls.append(url)  # pylint: disable=unnecessary-lambda
    protocol.get_tracked_urls = lambda: tracked_urls
    protocol.set_http_handlers = lambda http_get_handler=None, http_post_handler=None, http_put_handler=None:\
        http_handlers(get=http_get_handler, post=http_post_handler, put=http_put_handler)

    # go do it
    try:
        protocol.start()
        protocol.detect()
        yield protocol
    finally:
        protocol.stop()


class HttpRequestPredicates(object):
    """
    Utility functions to check the urls used by tests
    """
    @staticmethod
    def is_goal_state_request(url):
        return url.lower() == 'http://{0}/machine/?comp=goalstate'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_telemetry_request(url):
        return url.lower() == 'http://{0}/machine?comp=telemetrydata'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_health_service_request(url):
        return url.lower() == 'http://{0}:80/healthservice'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_in_vm_artifacts_profile_request(url):
        return re.match(r'https://.+\.blob\.core\.windows\.net/\$system/.+\.(vmSettings|settings)\?.+', url) is not None

    @staticmethod
    def _get_host_plugin_request_artifact_location(url, request_kwargs):
        if 'headers' not in request_kwargs:
            raise ValueError('Host plugin request is missing HTTP headers ({0})'.format(url))
        headers = request_kwargs['headers']
        if 'x-ms-artifact-location' not in headers:
            raise ValueError('Host plugin request is missing the x-ms-artifact-location header ({0})'.format(url))
        return headers['x-ms-artifact-location']

    @staticmethod
    def is_host_plugin_health_request(url):
        return url.lower() == 'http://{0}:{1}/health'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_extension_artifact_request(url):
        return url.lower() == 'http://{0}:{1}/extensionartifact'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_status_request(url):
        return url.lower() == 'http://{0}:{1}/status'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_extension_request(request_url, request_kwargs, extension_url):
        if not HttpRequestPredicates.is_host_plugin_extension_artifact_request(request_url):
            return False
        artifact_location = HttpRequestPredicates._get_host_plugin_request_artifact_location(request_url, request_kwargs)
        return artifact_location == extension_url

    @staticmethod
    def is_host_plugin_in_vm_artifacts_profile_request(url, request_kwargs):
        if not HttpRequestPredicates.is_host_plugin_extension_artifact_request(url):
            return False
        artifact_location = HttpRequestPredicates._get_host_plugin_request_artifact_location(url, request_kwargs)
        return HttpRequestPredicates.is_in_vm_artifacts_profile_request(artifact_location)

    @staticmethod
    def is_host_plugin_put_logs_request(url):
        return url.lower() == 'http://{0}:{1}/vmagentlog'.format(restutil.KNOWN_WIRESERVER_IP,
                                                                 restutil.HOST_PLUGIN_PORT)


class MockHttpResponse:
    def __init__(self, status, body=''):
        self.body = body
        self.status = status

    def read(self, *_):
        return self.body
