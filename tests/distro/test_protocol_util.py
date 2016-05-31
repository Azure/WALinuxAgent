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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

from tests.tools import *
from azurelinuxagent.distro.loader import get_distro
from azurelinuxagent.exception import *
from azurelinuxagent.distro.default.protocolUtil import *

@patch("time.sleep")
class TestProtocolUtil(AgentTestCase):
    
    @distros()
    @patch("azurelinuxagent.distro.default.protocolUtil.MetadataProtocol")
    @patch("azurelinuxagent.distro.default.protocolUtil.WireProtocol")
    def test_detect_protocol(self, distro_name, distro_version, distro_full_name, 
                             WireProtocol, MetadataProtocol, _, *distro_args):

        WireProtocol.return_value = MagicMock()
        MetadataProtocol.return_value = MagicMock()
        
        distro = get_distro(distro_name, distro_version, distro_full_name)
        distro.dhcp_handler = MagicMock()
        distro.dhcp_handler.endpoint = "foo.bar"

        #Test wire protocol is available
        protocol = distro.protocol_util.detect_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)

        #Test wire protocol is not available
        distro.protocol_util.protocol = None
        WireProtocol.side_effect = ProtocolError()

        protocol = distro.protocol_util.detect_protocol()
        self.assertEquals(MetadataProtocol.return_value, protocol)

        #Test no protocol is available
        distro.protocol_util.protocol = None
        WireProtocol.side_effect = ProtocolError()
        MetadataProtocol.side_effect = ProtocolError()
        self.assertRaises(ProtocolError, distro.protocol_util.detect_protocol)

    @distros()
    def test_detect_protocol_by_file(self, distro_name, distro_version, 
                                     distro_full_name, _):
        distro = get_distro(distro_name, distro_version, distro_full_name)
        protocol_util = distro.protocol_util

        protocol_util._detect_wire_protocol = Mock()
        protocol_util._detect_metadata_protocol = Mock()

        tag_file = os.path.join(self.tmp_dir, TAG_FILE_NAME)

        #Test tag file doesn't exist
        protocol_util.detect_protocol_by_file()
        protocol_util._detect_wire_protocol.assert_any_call()
        protocol_util._detect_metadata_protocol.assert_not_called()

        #Test tag file exists
        protocol_util.protocol = None
        protocol_util._detect_wire_protocol.reset_mock()
        protocol_util._detect_metadata_protocol.reset_mock()
        with open(tag_file, "w+") as tag_fd:
            tag_fd.write("")

        protocol_util.detect_protocol_by_file()
        protocol_util._detect_metadata_protocol.assert_any_call()
        protocol_util._detect_wire_protocol.assert_not_called()


if __name__ == '__main__':
    unittest.main()

