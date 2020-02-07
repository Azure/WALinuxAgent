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
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from tests.tools import patch


@contextlib.contextmanager
def create(mock_wire_data):

    mock_http_get = patch("azurelinuxagent.common.utils.restutil.http_get", side_effect=mock_wire_data.mock_http_get)
    mock_crypt_util = patch("azurelinuxagent.common.protocol.wire.CryptUtil", side_effect=mock_wire_data.mock_crypt_util)

    mock_http_get.start()
    mock_crypt_util.start()

    protocol = WireProtocol(KNOWN_WIRESERVER_IP)
    protocol.mock_data = mock_wire_data
    protocol.detect()

    try:
        yield protocol
    finally:
        mock_crypt_util.stop()
        mock_http_get.stop()
