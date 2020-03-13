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

import unittest
import os
import tempfile
from multiprocessing import Queue
from threading import Thread

from tests.tools import AgentTestCase, MagicMock, Mock, patch, clear_singleton_instances
from azurelinuxagent.common.exception import *
from azurelinuxagent.common.protocol.metadata_server_migration_util import _METADATA_PROTOCOL_NAME, \
                                                                           _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_P7B_FILE_NAME
from azurelinuxagent.common.protocol.goal_state import TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME
from azurelinuxagent.common.protocol.util import get_protocol_util, ProtocolUtil, PROTOCOL_FILE_NAME, WIRE_PROTOCOL_NAME, ENDPOINT_FILE_NAME
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from errno import ENOENT

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
        dir = tempfile.gettempdir()
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
        def get_util_obj(q, err):
            try:
                q.put(get_protocol_util())
            except Exception as e:
                err.put(str(e))

        queue = Queue()
        errors = Queue()
        t1 = Thread(target=get_util_obj, args=(queue, errors))
        t2 = Thread(target=get_util_obj, args=(queue, errors))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        errs = []
        while not errors.empty():
            errs.append(errors.get())
        if len(errs) > 0:
            raise Exception("Unable to fetch protocol_util. Errors: %s" % ' , '.join(errs))

        self.assertEqual(2, queue.qsize())  # Assert that there are 2 objects in the queue
        self.assertNotEqual(queue.get(), queue.get())
    
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_protocol(self, WireProtocol, _):
        WireProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        
        protocol_util.dhcp_handler = MagicMock()
        protocol_util.dhcp_handler.endpoint = "foo.bar"

        # Test wire protocol is available
        protocol = protocol_util.get_protocol()
        self.assertEquals(WireProtocol.return_value, protocol)

        # Test wire protocol is not available
        protocol_util.clear_protocol()
        WireProtocol.return_value.detect.side_effect = ProtocolError()

        self.assertRaises(ProtocolError, protocol_util.get_protocol)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_detect_protocol_no_dhcp(self, WireProtocol, mock_get_lib_dir, _):
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
        protocol_util._detect_protocol()
        self.assertEqual(KNOWN_WIRESERVER_IP, protocol_util.get_wireserver_endpoint())

        # Test wire protocol on dhcp failure
        protocol_util.osutil.is_dhcp_available.return_value = True
        protocol_util.dhcp_handler.run.side_effect = DhcpError()

        self.assertRaises(ProtocolError, protocol_util._detect_protocol)

    @patch("azurelinuxagent.common.protocol.util.WireProtocol")
    def test_get_protocol(self, WireProtocol, _):
        WireProtocol.return_value = MagicMock()

        protocol_util = get_protocol_util()
        protocol_util.get_wireserver_endpoint = Mock()
        protocol_util._detect_protocol = MagicMock()
        protocol_util._save_protocol("WireProtocol")

        protocol = protocol_util.get_protocol()

        self.assertEquals(WireProtocol.return_value, protocol)
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
        dir = tempfile.gettempdir()
        filename = os.path.join(dir, PROTOCOL_FILE_NAME)
        with open(filename, "w") as f:
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
            assert not os.path.exists(mds_cert_path)

        # Check firewall rules was reset
        protocol_util.osutil.remove_rules_files.assert_called_once()
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
        dir = tempfile.gettempdir()
        protocol_filename = os.path.join(dir, PROTOCOL_FILE_NAME)
        with open(protocol_filename, "w") as f:
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
            assert not os.path.exists(mds_cert_path)

        # Check that WireServer Certs exist
        ws_cert_paths = [os.path.join(dir, ws_cert) for ws_cert in TestProtocolUtil.WIRESERVER_CERTIFICATES]
        for ws_cert_path in ws_cert_paths:
            assert os.path.isfile(ws_cert_path)

        # Check firewall rules was reset
        protocol_util.osutil.remove_rules_files.assert_called_once()
        protocol_util.osutil.remove_firewall.assert_called_once()
        protocol_util.osutil.enable_firewall.assert_called_once()

        # Check Protocol File is updated to WireProtocol
        with open(os.path.join(dir, PROTOCOL_FILE_NAME), "r") as f:
            assert f.read() == WIRE_PROTOCOL_NAME
        
        # Check Endpoint file is updated to WireServer IP
        with open(os.path.join(dir, ENDPOINT_FILE_NAME), 'r') as f:
            assert f.read() == KNOWN_WIRESERVER_IP

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.protocol.wire.WireClient')
    def test_get_protocol_new_wireserver_agent_generates_certificates(self, mock_wire_client, mock_enable_firewall, mock_get_lib_dir, _):
        """
        This is for testing that a new WireServer Linux Agent generates appropriate certificates,
        protocol file, and endpoint file.
        """
        # Setup mocks
        dir = tempfile.gettempdir()
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
            assert os.path.isfile(ws_cert_path)

        # Check firewall rules were not reset
        protocol_util.osutil.remove_rules_files.assert_not_called()
        protocol_util.osutil.remove_firewall.assert_not_called()
        protocol_util.osutil.enable_firewall.assert_not_called()

        # Check Protocol File is updated to WireProtocol
        with open(protocol_filename, "r") as f:
            assert f.read() == WIRE_PROTOCOL_NAME
        
        # Check Endpoint file is updated to WireServer IP
        with open(os.path.join(dir, ENDPOINT_FILE_NAME), 'r') as f:
            assert f.read() == KNOWN_WIRESERVER_IP

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

