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
from tests.protocol.mockwiredata import *
from azurelinuxagent.exception import *
from azurelinuxagent.distro.loader import get_distro
from azurelinuxagent.protocol.restapi import get_properties
from azurelinuxagent.protocol.wire import WireProtocol

@patch("time.sleep")
@patch("azurelinuxagent.protocol.wire.CryptUtil")
@patch("azurelinuxagent.utils.restutil.http_get")
class TestExtension(AgentTestCase):

    def _assert_handler_status(self, report_vm_status, expected_status, 
                               expected_ext_count, version):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertNotEquals(0, len(vm_status.vmAgent.extensionHandlers))
        handler_status = vm_status.vmAgent.extensionHandlers[0]
        self.assertEquals(expected_status, handler_status.status)
        self.assertEquals("OSTCExtensions.ExampleHandlerLinux", 
                          handler_status.name)
        self.assertEquals(version, handler_status.version)
        self.assertEquals(expected_ext_count, len(handler_status.extensions))
    
    def _assert_no_handler_status(self, report_vm_status):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertEquals(0, len(vm_status.vmAgent.extensionHandlers))

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil, _):
        """Test enable/disable/unistall of an extension"""
        distro = get_distro()
        
        #Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()
        distro.protocol_util.get_protocol = Mock(return_value=protocol)
        
        return distro, protocol
        
    def test_ext_handler(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        distro, protocol = self._create_mock(test_data, *args)

        #Test enable scenario. 
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test goal state not changed
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")

        #Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"", 
                                                        "seqNo=\"1\"")
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        
        #Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0", "1.1")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"", 
                                                        "seqNo=\"2\"")
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        #Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 
                                    1, "1.1")

        #Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        distro.ext_handlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        #Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        distro.ext_handlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_handler_no_settings(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_NO_SETTINGS)
        distro, protocol = self._create_mock(test_data, *args)

        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0")

    def test_ext_handler_no_public_settings(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_NO_PUBLIC)
        distro, protocol = self._create_mock(test_data, *args)

        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")

    def test_ext_handler_no_ext(self, *args):
        test_data = WireProtocolData(DATA_FILE_NO_EXT)
        distro, protocol = self._create_mock(test_data, *args)

        #Assert no extension handler status
        distro.ext_handlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
    
    @patch('azurelinuxagent.distro.default.extension.add_event')
    def test_ext_handler_download_failure(self, mock_add_event, *args):
        test_data = WireProtocolData(DATA_FILE)
        distro, protocol = self._create_mock(test_data, *args)
        protocol.download_ext_handler_pkg = Mock(side_effect=ProtocolError)

        distro.ext_handlers_handler.run()
        args, kw = mock_add_event.call_args
        self.assertEquals(False, kw['is_success'])
        self.assertEquals("OSTCExtensions.ExampleHandlerLinux", kw['name'])
        self.assertEquals("Download", kw['op'])

    @patch('azurelinuxagent.distro.default.extension.fileutil')
    def test_ext_handler_io_error(self, mock_fileutil, *args):
        test_data = WireProtocolData(DATA_FILE)
        distro, protocol = self._create_mock(test_data, *args)
    
        mock_fileutil.write_file.return_value = IOError("Mock IO Error")
        distro.ext_handlers_handler.run()

    def _assert_ext_status(self, report_ext_status, expected_status, 
                           expected_seq_no):
        self.assertTrue(report_ext_status.called)
        args, kw = report_ext_status.call_args
        ext_status = args[-1]
        self.assertEquals(expected_status, ext_status.status)
        self.assertEquals(expected_seq_no, ext_status.sequenceNumber)

    def test_ext_handler_no_reporting_status(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        distro, protocol = self._create_mock(test_data, *args)
        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")

        #Remove status file and re-run collecting extension status
        status_file = os.path.join(self.tmp_dir, 
                                   "OSTCExtensions.ExampleHandlerLinux-1.0",
                                   "status", "0.status")
        self.assertTrue(os.path.isfile(status_file))
        os.remove(status_file)

        distro.ext_handlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0")
        self._assert_ext_status(protocol.report_ext_status, "error", 0)


if __name__ == '__main__':
    unittest.main()

