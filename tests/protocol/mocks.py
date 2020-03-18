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
from tests.protocol.mockwiredata import WireProtocolData


@contextlib.contextmanager
def mock_wire_protocol(mock_wire_data_file):
    """
    Creates a mock WireProtocol object that will return the data specified by 'mock_wire_data_file' (which must
    follow the structure of the data files defined in tests/protocol/mockwiredata.py).

    NOTE: This function creates mocks for azurelinuxagent.common.utils.restutil.http_request and
          azurelinuxagent.common.protocol.wire.CryptUtil. These mocks can be stopped using the
          methods stop_mock_http_get() and stop_mock_crypt_util().

    The return value is an instance of WireProtocol augmented with these properties/methods:

        * mock_wire_data - the WireProtocolData constructed from the mock_wire_data_file parameter.
        * stop_mock_http_request() - stops the mock for restutil.http_request
        * stop_mock_crypt_util() - stops the mock for CrypUtil
        * stop() - stops both mocks
    """
    def stop_mock_http_request():
        if stop_mock_http_request.mock is not None:
            stop_mock_http_request.mock.stop()
            stop_mock_http_request.mock = None
    stop_mock_http_request.mock = None

    def stop_mock_crypt_util():
        if stop_mock_crypt_util.mock is not None:
            stop_mock_crypt_util.mock.stop()
            stop_mock_crypt_util.mock = None
    stop_mock_crypt_util.mock = None

    def stop():
        stop_mock_crypt_util()
        stop_mock_http_request()

    protocol = WireProtocol(restutil.KNOWN_WIRESERVER_IP)
    protocol.mock_wire_data = WireProtocolData(mock_wire_data_file)
    protocol.stop_mock_http_request = stop_mock_http_request
    protocol.stop_mock_crypt_util = stop_mock_crypt_util
    protocol.stop = stop

    try:
        # To minimize the impact of mocking restutil.http_request we only use the mock data for requests
        # to the wireserver or requests starting with "mock-goal-state"
        mock_data_re = re.compile(r'https?://(mock-goal-state|{0}).*'.format(restutil.KNOWN_WIRESERVER_IP.replace(r'.', r'\.')), re.IGNORECASE)

        original_http_request = restutil.http_request

        def http_request(method, url, data, **kwargs):
            if method == 'GET' and mock_data_re.match(url) is not None:
                return protocol.mock_wire_data.mock_http_get(url, **kwargs)
            elif method == 'POST':
                return protocol.mock_wire_data.mock_http_post(url, data, **kwargs)
            return original_http_request(method, url, data, **kwargs)

        patched = patch("azurelinuxagent.common.utils.restutil.http_request", side_effect=http_request)
        patched.start()
        stop_mock_http_request.mock = patched

        patched = patch("azurelinuxagent.common.protocol.wire.CryptUtil", side_effect=protocol.mock_wire_data.mock_crypt_util)
        patched.start()
        stop_mock_crypt_util.mock = patched

        protocol.detect()

        yield protocol

    finally:
        protocol.stop()


@contextlib.contextmanager
def mock_http_request(http_get_handler=None, http_post_handler=None, http_put_handler=None):
    """
    Creates a Mock of restutil.http_request that executes the handler given for the corresponding HTTP method.

    The return value of the handler function is interpreted similarly to the "return_value" argument of patch(): if it
    is an exception the exception is raised or, if it is any object other than None, the value is returned by the mock.

    If the handler function returns None the call is passed to the original restutil.http_request.

    The patch maintains a list of "tracked" urls. When the handler function returns a value than is not None the url
    for the request is automatically added to the tracked list. The handler function can add other items to this list
    using the track_url() method on the mock.

    The returned Mock is augmented with these 2 methods:

        * track_url(url) - adds the given item to the list of tracked urls.
        * get_tracked_urls() - returns the list of tracked urls.
    """
    tracked_urls = []
    original_http_request = restutil.http_request

    def http_request(method, url, *args, **kwargs):
        handler = None
        if method == 'GET':
            handler = http_get_handler
        elif method == 'POST':
            handler = http_post_handler
        elif method == 'PUT':
            handler = http_put_handler

        if handler is not None:
            return_value = handler(url, *args, **kwargs)
            if return_value is not None:
                tracked_urls.append(url)
                if isinstance(return_value, Exception):
                    raise return_value
                return return_value

        return original_http_request(method, url, *args, **kwargs)

    patched = patch("azurelinuxagent.common.utils.restutil.http_request", side_effect=http_request)
    patched.track_url = lambda url: tracked_urls.append(url)
    patched.get_tracked_urls = lambda: tracked_urls
    patched.start()
    try:
        yield patched
    finally:
        patched.stop()
