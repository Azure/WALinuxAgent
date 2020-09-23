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
import tempfile
import unittest
from errno import ENOENT
from threading import Thread

from azurelinuxagent.common.exception import ProtocolError, DhcpError, OSUtilError
from azurelinuxagent.common.protocol.goal_state import TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME
from azurelinuxagent.common.protocol.metadata_server_migration_util import _METADATA_PROTOCOL_NAME, \
    _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
    _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
    _LEGACY_METADATA_SERVER_P7B_FILE_NAME
from azurelinuxagent.common.protocol.util import get_protocol_util, ProtocolUtil, PROTOCOL_FILE_NAME, \
    WIRE_PROTOCOL_NAME, ENDPOINT_FILE_NAME
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from tests.tools import AgentTestCase, MagicMock, Mock, patch, clear_singleton_instances


@patch("time.sleep")
class TestProtocolUtil(AgentTestCase):
    MDS_CERTIFICATES = [_LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
                        _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
                        _LEGACY_METADATA_SERVER_P7B_FILE_NAME]
    WIRESERVER_CERTIFICATES = [TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME]

    def setUp(self):
        super(TestProtocolUtil, self).setUp()
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    # Cleanup certificate files, protocol file, and endpoint files
    def tearDown(self):
        dir = tempfile.gettempdir() # pylint: disable=redefined-builtin
        for path in [os.path.join(dir, mds_cert) for mds_cert in TestProtocolUtil.MDS_CERTIFICATES]:
            if os.path.exists(path):
                os.remove(path)
        for path in [os.path.join(dir, ws_cert) for ws_cert in TestProtocolUtil.WIRESERVER_CERTIFICATES]:
            if os.path.exists(path):
                os.remove(path)
        protocol_path = os.path.join(dir, PROTOCOL_FILE_NAME)
        if os.path.exists(protocol_path):
            os.remove(protocol_path)
        endpoint_path = os.path.join(dir, ENDPOINT_FILE_NAME)
        if os.path.exists(endpoint_path):
            os.remove(endpoint_path)

    def test_get_protocol_util_should_return_same_object_for_same_thread(self, _):
        protocol_util1 = get_protocol_util()
        protocol_util2 = get_protocol_util()

        self.assertEqual(protocol_util1, protocol_util2)

    def test_get_protocol_util_should_return_different_object_for_different_thread(self, _):
        protocol_util_instances = []
        errors = []

        def get_protocol_util_instance():
            try:
                protocol_util_instances.append(get_protocol_util())
            except Exception as e: # pylint: disable=invalid-name
                errors.append(e)

        t1 = Thread(target=get_protocol_util_instance) # pylint: disable=invalid-name
        t2 = Thread(target=get_protocol_util_instance) # pylint: disable=invalid-name
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(protocol_util_instances), 2, "Could not create the expected number of protocols. Errors: [{0}]".format(errors))
        self.assertNotEqual(protocol_util_instances[0], protocol_util_instances[1], "The instances created by different threads should be different")
    
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_protocol(self, WireProtocol, _): # pylint: disable=invalid-name
        WireProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = "foo.bar"

        # Test wire protocol is available
        protocol = protocol_util.get_protocol()
        self.assertEqual(WireProtocol.return_value, protocol)

        # Test wire protocol is not available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()

        self.assertRaises(ProtocolError, protocol_util.get_protocol)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_protocol_no_dhcp(self, WireProtocol, mock_get_lib_dir, _): # pylint: disable=invalid-name
        WireProtocol.return_value.detect = Mock()
        mock_get_lib_dir.return_value = self.tmp_dir

        protocol_util = get_protocol_util()

        protocol_util.osutil = MagicMock()
        protocol_util.osutil.is_dhcp_available.return_value = False

        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = None
        protocol_util.dhcp_handler.run = Mock()

        endpoint_file = protocol_util._get_wireserver_endpoint_file_path() # pylint: disable=unused-variable,protected-access

        # Test wire protocol when no endpoint file has been written
        protocol_util._detect_protocol() # pylint: disable=protected-access
        self.assertEqual(KNOWN_WIRESERVER_IP, protocol_util.get_wireserver_endpoint())

        # Test wire protocol on dhcp failure
        protocol_util.osutil.is_dhcp_available.return_value = True
        protocol_util.dhcp_handler.run.side_effect = DhcpError()

        self.assertRaises(ProtocolError, protocol_util._detect_protocol) # pylint: disable=protected-access

    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_get_protocol(self, WireProtocol, _): # pylint: disable=invalid-name
        WireProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        protocol_util.get_wireserver_endpoint = Mock()
        protocol_util._detect_protocol = MagicMock() # pylint: disable=protected-access
        protocol_util._save_protocol("WireProtocol") # pylint: disable=protected-access

        protocol = protocol_util.get_protocol()

        self.assertEqual(WireProtocol.return_value, protocol)
        protocol_util.get_wireserver_endpoint.assert_any_call()

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    def test_get_protocol_wireserver_to_wireserver_update_removes_metadataserver_artifacts(self, mock_enable_firewall, mock_get_lib_dir, _):
        """
        This is for testing that agent upgrade from WireServer to WireServer protocol
        will clean up leftover MDS Certificates (from a previous Metadata Server to Wireserver
        update, intermediate updated agent does not clean up MDS certificates) and reset firewall rules.
        We don't test that WireServer certificates, protocol file, or endpoint file were created
        because we already expect them to be created since we are updating from a WireServer agent.
        """
        # Setup Protocol file with WireProtocol
        dir = tempfile.gettempdir() # pylint: disable=redefined-builtin
        filename = os.path.join(dir, PROTOCOL_FILE_NAME)
        with open(filename, "w") as f: # pylint: disable=invalid-name
            f.write(WIRE_PROTOCOL_NAME)

        # Setup MDS Certificates
        mds_cert_paths = [os.path.join(dir, mds_cert) for mds_cert in TestProtocolUtil.MDS_CERTIFICATES]
        for mds_cert_path in mds_cert_paths:
            open(mds_cert_path, "w").close()

        # Setup mocks
        mock_get_lib_dir.return_value = dir
        mock_enable_firewall.return_value = True
        protocol_util = get_protocol_util()
        protocol_util.osutil = MagicMock()
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = KNOWN_WIRESERVER_IP

        # Run
        protocol_util.get_protocol()

        # Check MDS Certs do not exist
        for mds_cert_path in mds_cert_paths:
            self.assertFalse(os.path.exists(mds_cert_path))

        # Check firewall rules was reset
        protocol_util.osutil.remove_firewall.assert_called_once()
        protocol_util.osutil.enable_firewall.assert_called_once()

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.protocol.wire.WireClient')
    def test_get_protocol_metadataserver_to_wireserver_update_removes_metadataserver_artifacts(self, mock_wire_client, mock_enable_firewall, mock_get_lib_dir, _):
        """
        This is for testing that agent upgrade from MetadataServer to WireServer protocol
        will clean up leftover MDS Certificates and reset firewall rules. Also check that
        WireServer certificates are present, and protocol/endpoint files are written to appropriately.
        """
        # Setup Protocol file with MetadataProtocol
        dir = tempfile.gettempdir() # pylint: disable=redefined-builtin
        protocol_filename = os.path.join(dir, PROTOCOL_FILE_NAME)
        with open(protocol_filename, "w") as f: # pylint: disable=invalid-name
            f.write(_METADATA_PROTOCOL_NAME)

        # Setup MDS Certificates
        mds_cert_paths = [os.path.join(dir, mds_cert) for mds_cert in TestProtocolUtil.MDS_CERTIFICATES]
        for mds_cert_path in mds_cert_paths:
            open(mds_cert_path, "w").close()

        # Setup mocks
        mock_get_lib_dir.return_value = dir
        mock_enable_firewall.return_value = True
        protocol_util = get_protocol_util()
        protocol_util.osutil = MagicMock()
        mock_wire_client.return_value = MagicMock()
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = KNOWN_WIRESERVER_IP

        # Run
        protocol_util.get_protocol()

        # Check MDS Certs do not exist
        for mds_cert_path in mds_cert_paths:
            self.assertFalse(os.path.exists(mds_cert_path))

        # Check that WireServer Certs exist
        ws_cert_paths = [os.path.join(dir, ws_cert) for ws_cert in TestProtocolUtil.WIRESERVER_CERTIFICATES]
        for ws_cert_path in ws_cert_paths:
            self.assertTrue(os.path.isfile(ws_cert_path))

        # Check firewall rules was reset
        protocol_util.osutil.remove_firewall.assert_called_once()
        protocol_util.osutil.enable_firewall.assert_called_once()

        # Check Protocol File is updated to WireProtocol
        with open(os.path.join(dir, PROTOCOL_FILE_NAME), "r") as f: # pylint: disable=invalid-name
            self.assertEqual(f.read(), WIRE_PROTOCOL_NAME)
        
        # Check Endpoint file is updated to WireServer IP
        with open(os.path.join(dir, ENDPOINT_FILE_NAME), 'r') as f: # pylint: disable=invalid-name
            self.assertEqual(f.read(), KNOWN_WIRESERVER_IP)

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.protocol.wire.WireClient')
    def test_get_protocol_new_wireserver_agent_generates_certificates(self, mock_wire_client, mock_enable_firewall, mock_get_lib_dir, _):
        """
        This is for testing that a new WireServer Linux Agent generates appropriate certificates,
        protocol file, and endpoint file.
        """
        # Setup mocks
        dir = tempfile.gettempdir() # pylint: disable=redefined-builtin
        mock_get_lib_dir.return_value = dir
        mock_enable_firewall.return_value = True
        protocol_util = get_protocol_util()
        protocol_util.osutil = MagicMock()
        mock_wire_client.return_value = MagicMock()
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = KNOWN_WIRESERVER_IP

        # Run
        protocol_util.get_protocol()

        # Check that WireServer Certs exist
        ws_cert_paths = [os.path.join(dir, ws_cert) for ws_cert in TestProtocolUtil.WIRESERVER_CERTIFICATES]
        for ws_cert_path in ws_cert_paths:
            self.assertTrue(os.path.isfile(ws_cert_path))

        # Check firewall rules were not reset
        protocol_util.osutil.remove_firewall.assert_not_called()
        protocol_util.osutil.enable_firewall.assert_not_called()

        # Check Protocol File is updated to WireProtocol
        with open(os.path.join(dir, PROTOCOL_FILE_NAME), "r") as f: # pylint: disable=invalid-name
            self.assertEqual(f.read(), WIRE_PROTOCOL_NAME)
        
        # Check Endpoint file is updated to WireServer IP
        with open(os.path.join(dir, ENDPOINT_FILE_NAME), 'r') as f: # pylint: disable=invalid-name
            self.assertEqual(f.read(), KNOWN_WIRESERVER_IP)

    @patch("azurelinuxagent.common.protocol.util.fileutil")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_endpoint_file_states(self, mock_get_lib_dir, mock_fileutil, _):
        mock_get_lib_dir.return_value = self.tmp_dir

        protocol_util = get_protocol_util()
        endpoint_file = protocol_util._get_wireserver_endpoint_file_path() # pylint: disable=protected-access

        # Test get endpoint for io error
        mock_fileutil.read_file.side_effect = IOError()

        ep = protocol_util.get_wireserver_endpoint() # pylint: disable=invalid-name
        self.assertEqual(ep, KNOWN_WIRESERVER_IP)

        # Test get endpoint when file not found
        mock_fileutil.read_file.side_effect = IOError(ENOENT, 'File not found')

        ep = protocol_util.get_wireserver_endpoint() # pylint: disable=invalid-name
        self.assertEqual(ep, KNOWN_WIRESERVER_IP)

        # Test get endpoint for empty file
        mock_fileutil.read_file.return_value = ""

        ep = protocol_util.get_wireserver_endpoint() # pylint: disable=invalid-name
        self.assertEqual(ep, KNOWN_WIRESERVER_IP)

        # Test set endpoint for io error
        mock_fileutil.write_file.side_effect = IOError()

        ep = protocol_util.get_wireserver_endpoint() # pylint: disable=invalid-name
        self.assertRaises(OSUtilError, protocol_util._set_wireserver_endpoint, 'abc') # pylint: disable=protected-access

        # Test clear endpoint for io error
        with open(endpoint_file, "w+") as ep_fd:
            ep_fd.write("")

        with patch('os.remove') as mock_remove:
            protocol_util._clear_wireserver_endpoint() # pylint: disable=protected-access
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(endpoint_file, mock_remove.call_args_list[0][0][0])

        # Test clear endpoint when file not found
        with patch('os.remove') as mock_remove:
            mock_remove = Mock(side_effect=IOError(ENOENT, 'File not found'))
            protocol_util._clear_wireserver_endpoint() # pylint: disable=protected-access
            mock_remove.assert_not_called()

    def test_protocol_file_states(self, _):
        protocol_util = get_protocol_util()
        protocol_util._clear_wireserver_endpoint = Mock() # pylint: disable=protected-access

        protocol_file = protocol_util._get_protocol_file_path() # pylint: disable=protected-access

        # Test clear protocol for io error
        with open(protocol_file, "w+") as proto_fd:
            proto_fd.write("")

        with patch('os.remove') as mock_remove:
            protocol_util.clear_protocol()
            self.assertEqual(1, protocol_util._clear_wireserver_endpoint.call_count) # pylint: disable=protected-access
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(protocol_file, mock_remove.call_args_list[0][0][0])

        # Test clear protocol when file not found
        protocol_util._clear_wireserver_endpoint.reset_mock() # pylint: disable=protected-access

        with patch('os.remove') as mock_remove:
            protocol_util.clear_protocol()
            self.assertEqual(1, protocol_util._clear_wireserver_endpoint.call_count) # pylint: disable=protected-access
            self.assertEqual(1, mock_remove.call_count)
            self.assertEqual(protocol_file, mock_remove.call_args_list[0][0][0])


if __name__ == '__main__':
    unittest.main()

