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
from azurelinuxagent.common.exception import *
from azurelinuxagent.common.protocol import get_protocol_util, \
                                            TAG_FILE_NAME

@patch("time.sleep")
class TestProtocolUtil(AgentTestCase):
    
    @patch("azurelinuxagent.common.protocol.util.MetadataProtocol")
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_protocol(self, WireProtocol, MetadataProtocol, _):
        WireProtocol.return_value = MagicMock()
        MetadataProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = "foo.bar"

        #Test wire protocol is available
        protocol = protocol_util.get_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)

        #Test wire protocol is not available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()

        protocol = protocol_util.get_protocol()
        self.assertEquals(MetadataProtocol.return_value, protocol)

        #Test no protocol is available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()

        MetadataProtocol.return_value.detect.side_effect = ProtocolError()
        self.assertRaises(ProtocolError, protocol_util.get_protocol)

    def test_detect_protocol_by_file(self, _):
        protocol_util = get_protocol_util()
        protocol_util._detect_wire_protocol = Mock()
        protocol_util._detect_metadata_protocol = Mock()

        tag_file = os.path.join(self.tmp_dir, TAG_FILE_NAME)

        #Test tag file doesn't exist
        protocol_util.get_protocol_by_file()
        protocol_util._detect_wire_protocol.assert_any_call()
        protocol_util._detect_metadata_protocol.assert_not_called()

        #Test tag file exists
        protocol_util.clear_protocol()
        protocol_util._detect_wire_protocol.reset_mock()
        protocol_util._detect_metadata_protocol.reset_mock()
        with open(tag_file, "w+") as tag_fd:
            tag_fd.write("")

        protocol_util.get_protocol_by_file()
        protocol_util._detect_metadata_protocol.assert_any_call()
        protocol_util._detect_wire_protocol.assert_not_called()


if __name__ == '__main__':
    unittest.main()

