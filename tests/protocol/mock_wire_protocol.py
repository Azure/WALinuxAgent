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
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP, http_get
from tests.tools import patch
from tests.protocol.mockwiredata import WireProtocolData

@contextlib.contextmanager
def create(mock_wire_data_file):
    """
    Creates a mock WireProtocol object that will return the data specified by 'mock_wire_data_file' (which must
    follow the structure of the data files defined in tests/protocol/mockwiredata.py).

    NOTE: This function creates mocks for azurelinuxagent.common.utils.restutil.http_get and
          azurelinuxagent.common.protocol.wire.CryptUtil. These mocks can be stopped using the
          methods stop_mock_http_get() and stop_mock_crypt_util().

    The return value is an instance of WireProtocol augmented with these properties/methods:

        * mock_wire_data - the WireProtocolData constructed from the mock_wire_data_file parameter.
        * stop_mock_http_get() - stops the mock for restutil.http_get
        * stop_mock_crypt_util() - stops the mock for CrypUtil
    """
    def stop_mock_http_get():
        if stop_mock_http_get.mock is not None:
            stop_mock_http_get.mock.stop()
            stop_mock_http_get.mock = None
    stop_mock_http_get.mock = None

    def stop_mock_crypt_util():
        if stop_mock_crypt_util.mock is not None:
            stop_mock_crypt_util.mock.stop()
            stop_mock_crypt_util.mock = None
    stop_mock_crypt_util.mock = None

    protocol = WireProtocol(KNOWN_WIRESERVER_IP)
    protocol.mock_wire_data = WireProtocolData(mock_wire_data_file)
    protocol.stop_mock_http_get = stop_mock_http_get
    protocol.stop_mock_crypt_util = stop_mock_crypt_util

    try:
        # To minimize the impact of mocking restutil.http_get we only use the mock data for requests
        # to the wireserver or requests starting with "mock-goal-state"
        original_http_get = http_get

        mock_data_re = re.compile(r'https?://(mock-goal-state|{0}).*'.format(KNOWN_WIRESERVER_IP.replace(r'.', r'\.')), re.IGNORECASE)

        def mock_http_get(url, *args, **kwargs):
            if mock_data_re.match(url) is None:
                return original_http_get(url, *args, **kwargs)
            return protocol.mock_wire_data.mock_http_get(url, *args, **kwargs)

        p = patch("azurelinuxagent.common.utils.restutil.http_get", side_effect=mock_http_get)
        p.start()
        stop_mock_http_get.mock = p

        p = patch("azurelinuxagent.common.protocol.wire.CryptUtil", side_effect=protocol.mock_wire_data.mock_crypt_util)
        p.start()
        stop_mock_crypt_util.mock = p

        protocol.detect()

        yield protocol

    finally:
        protocol.stop_mock_crypt_util()
        protocol.stop_mock_http_get()
