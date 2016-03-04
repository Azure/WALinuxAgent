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

from tests.tools import *
from tests.protocol.mockmetadata import *
from azurelinuxagent.common.utils.restutil import httpclient
from azurelinuxagent.common.protocol.metadata import MetadataProtocol

@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.metadata.restutil")
class TestWireProtocolGetters(AgentTestCase):
    def _test_getters(self, test_data, mock_restutil ,_):
        mock_restutil.http_get.side_effect = test_data.mock_http_get

        protocol = MetadataProtocol()
        protocol.detect()
        protocol.get_vminfo()
        protocol.get_certs()
        ext_handlers, etag= protocol.get_ext_handlers()
        for ext_handler in ext_handlers.extHandlers:
            protocol.get_ext_handler_pkgs(ext_handler)

    def test_getters(self, *args):
        test_data = MetadataProtocolData(DATA_FILE)
        self._test_getters(test_data, *args)

    def test_getters_no(self, *args):
        test_data = MetadataProtocolData(DATA_FILE_NO_EXT)
        self._test_getters(test_data, *args)


