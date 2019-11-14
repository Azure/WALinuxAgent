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
import unittest

from tests.tools import AgentTestCase, MagicMock, Mock, patch
from azurelinuxagent.common.exception import *
from azurelinuxagent.common.protocol import get_protocol_util, \
                                            TAG_FILE_NAME
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from azurelinuxagent.common.protocol.util import ENDPOINT_FILE_NAME
from errno import ENOENT


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

        # Test wire protocol is available
        protocol = protocol_util.get_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)

        # Test wire protocol is not available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()

        protocol = protocol_util.get_protocol()
        self.assertEquals(MetadataProtocol.return_value, protocol)

        # Test no protocol is available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()
        MetadataProtocol.return_value.detect.side_effect = ProtocolError()

        self.assertRaises(ProtocolError, protocol_util.get_protocol)

    def test_detect_protocol_by_file(self, _):
        protocol_util = get_protocol_util()
        protocol_util._detect_wire_protocol = Mock()
        protocol_util._detect_metadata_protocol = Mock()

        tag_file = os.path.join(self.tmp_dir, TAG_FILE_NAME)

        # Test tag file doesn't exist
        protocol_util.get_protocol(by_file=True)
        protocol_util._detect_wire_protocol.assert_any_call()
        protocol_util._detect_metadata_protocol.assert_not_called()

        # Test tag file exists
        protocol_util.clear_protocol()
        protocol_util._detect_wire_protocol.reset_mock()
        protocol_util._detect_metadata_protocol.reset_mock()
        with open(tag_file, "w+") as tag_fd:
            tag_fd.write("")

        protocol_util.get_protocol(by_file=True)
        protocol_util._detect_metadata_protocol.assert_any_call()
        protocol_util._detect_wire_protocol.assert_not_called()

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_wire_protocol_no_dhcp(self, WireProtocol, mock_get_lib_dir, _):
        WireProtocol.return_value.detect = Mock()
        mock_get_lib_dir.return_value = self.tmp_dir

        protocol_util = get_protocol_util()

        protocol_util.osutil = MagicMock()
        protocol_util.osutil.is_dhcp_available.return_value = False

        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = None
        protocol_util.dhcp_handler.run = Mock()

        endpoint_file = protocol_util._get_wireserver_endpoint_file_path()

        # Test wire protocol when no endpoint file has been written
        protocol_util._detect_wire_protocol()
        self.assertEqual(KNOWN_WIRESERVER_IP, protocol_util.get_wireserver_endpoint())

        # Test wire protocol when endpoint was previously detected
        protocol_util.clear_protocol()
        with open(endpoint_file, "w+") as endpoint_fd:
            endpoint_fd.write("baz.qux")

        protocol_util._detect_wire_protocol()
        self.assertEqual("baz.qux", protocol_util.get_wireserver_endpoint())

        # Test wire protocol on dhcp failure
        protocol_util.clear_protocol()
        protocol_util.osutil.is_dhcp_available.return_value = True
        protocol_util.dhcp_handler.run.side_effect = DhcpError()

        self.assertRaises(ProtocolError, protocol_util._detect_wire_protocol)

    @patch("azurelinuxagent.common.protocol.util.MetadataProtocol")
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_get_protocol(self, WireProtocol, MetadataProtocol, _):
        WireProtocol.return_value = MagicMock()
        MetadataProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        protocol_util.get_wireserver_endpoint = Mock()
        protocol_util._detect_protocol = MagicMock()

        # Test for wire protocol
        protocol_util._save_protocol("WireProtocol")

        protocol = protocol_util.get_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)
        protocol_util.get_wireserver_endpoint.assert_any_call()

        # Test to ensure protocol persists
        protocol_util.get_wireserver_endpoint.reset_mock()
        protocol_util._save_protocol("MetadataProtocol")

        protocol = protocol_util.get_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)
        protocol_util.get_wireserver_endpoint.assert_not_called()

        # Test for metadata protocol
        protocol_util.clear_protocol()
        protocol_util._save_protocol("MetadataProtocol")

        protocol = protocol_util.get_protocol()
        self.assertEquals(MetadataProtocol.return_value, protocol)
        protocol_util.get_wireserver_endpoint.assert_not_called()

        # Test for unknown protocol
        protocol_util.clear_protocol()
        protocol_util._save_protocol("Not_a_Protocol")
        protocol_util._detect_protocol.side_effect = NotImplementedError()

        self.assertRaises(NotImplementedError, protocol_util.get_protocol)
        protocol_util.get_wireserver_endpoint.assert_not_called()

    @patch("azurelinuxagent.common.utils.fileutil")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_endpoint_file_states(self, mock_get_lib_dir, mock_fileutil, _):
        mock_get_lib_dir.return_value = self.tmp_dir
        mock_fileutil = MagicMock()

        protocol_util = get_protocol_util()
        endpoint_file = protocol_util._get_wireserver_endpoint_file_path()

        # Test get endpoint for io error
        mock_fileutil.read_file.side_effect = IOError()

        ep = protocol_util.get_wireserver_endpoint()
        self.assertEquals(ep, KNOWN_WIRESERVER_IP)

        # Test get endpoint when file not found
        mock_fileutil.read_file.side_effect = IOError(ENOENT, 'File not found')

        ep = protocol_util.get_wireserver_endpoint()
        self.assertEquals(ep, KNOWN_WIRESERVER_IP)

        # Test get endpoint for empty file
        mock_fileutil.read_file.return_value = ""

        ep = protocol_util.get_wireserver_endpoint()
        self.assertEquals(ep, KNOWN_WIRESERVER_IP)

        # Test set endpoint for io error
        mock_fileutil.write_file.side_effect = IOError()

        ep = protocol_util.get_wireserver_endpoint()
        self.assertRaises(OSUtilError, protocol_util._set_wireserver_endpoint('abc'))

        # Test clear endpoint for io error
        with open(endpoint_file, "w+") as ep_fd:
            ep_fd.write("")

        with patch('os.remove') as mock_remove:
            protocol_util._clear_wireserver_endpoint()
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(endpoint_file, mock_remove.call_args_list[0][0][0])

        # Test clear endpoint when file not found
        with patch('os.remove') as mock_remove:
            mock_remove = Mock(side_effect=IOError(ENOENT, 'File not found'))
            protocol_util._clear_wireserver_endpoint()
            mock_remove.assert_not_called()

    def test_protocol_file_states(self, _):
        protocol_util = get_protocol_util()
        protocol_util._clear_wireserver_endpoint = Mock()

        protocol_file = protocol_util._get_protocol_file_path()

        # Test clear protocol for io error
        with open(protocol_file, "w+") as proto_fd:
            proto_fd.write("")

        with patch('os.remove') as mock_remove:
            protocol_util.clear_protocol()
            self.assertEqual(1, protocol_util._clear_wireserver_endpoint.call_count)
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(protocol_file, mock_remove.call_args_list[0][0][0])

        # Test clear protocol when file not found
        protocol_util._clear_wireserver_endpoint.reset_mock()

        with patch('os.remove') as mock_remove:
            protocol_util.clear_protocol()
            self.assertEqual(1, protocol_util._clear_wireserver_endpoint.call_count)
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(protocol_file, mock_remove.call_args_list[0][0][0])


if __name__ == '__main__':
    unittest.main()

