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

from tests.protocol.mockwiredata import *
from azurelinuxagent.common.exception import *
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.ga.exthandlers import *
from azurelinuxagent.common.protocol.wire import WireProtocol

@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
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
        handler = get_exthandlers_handler()

        #Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util
 
        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        handler.protocol_util.get_protocol = Mock(return_value=protocol)
        
        return handler, protocol
        
    def test_ext_handler(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        #Test enable scenario. 
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        #Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"", 
                                                        "seqNo=\"1\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        
        #Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"", 
                                                        "seqNo=\"2\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        #Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 
                                    1, "1.1.0")

        #Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        #Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_handler_no_settings(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_NO_SETTINGS)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0.0")

    def test_ext_handler_no_public_settings(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_NO_PUBLIC)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

    def test_ext_handler_no_ext(self, *args):
        test_data = WireProtocolData(DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        #Assert no extension handler status
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
    
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_download_failure(self, mock_add_event, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.download_ext_handler_pkg = Mock(side_effect=ProtocolError)

        exthandlers_handler.run()
        args, kw = mock_add_event.call_args
        self.assertEquals(False, kw['is_success'])
        self.assertEquals("OSTCExtensions.ExampleHandlerLinux", kw['name'])
        self.assertEquals("Download", kw['op'])

    @patch('azurelinuxagent.ga.exthandlers.fileutil')
    def test_ext_handler_io_error(self, mock_fileutil, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
    
        mock_fileutil.write_file.return_value = IOError("Mock IO Error")
        exthandlers_handler.run()

    def _assert_ext_status(self, report_ext_status, expected_status, 
                           expected_seq_no):
        self.assertTrue(report_ext_status.called)
        args, kw = report_ext_status.call_args
        ext_status = args[-1]
        self.assertEquals(expected_status, ext_status.status)
        self.assertEquals(expected_seq_no, ext_status.sequenceNumber)

    def test_ext_handler_no_reporting_status(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        #Remove status file and re-run collecting extension status
        status_file = os.path.join(self.tmp_dir, 
                                   "OSTCExtensions.ExampleHandlerLinux-1.0.0",
                                   "status", "0.status")
        self.assertTrue(os.path.isfile(status_file))
        os.remove(status_file)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "error", 0)

    def test_ext_handler_version_decide_autoupgrade_internalversion(self, *args):
        for internal in [False, True]:
            for autoupgrade in [False, True]:
                # only python 3.4+ has subTest
                # with self.subTest(autoupgrade=autoupgrade, internal=internal):
                    if internal:
                        config_version = '1.2.0'
                        decision_version = '1.2.0'
                        if autoupgrade:
                            datafile = DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION
                        else:
                            datafile = DATA_FILE_EXT_INTERNALVERSION
                    else:
                        config_version = '1.0.0'
                        if autoupgrade:
                            datafile = DATA_FILE_EXT_AUTOUPGRADE
                            decision_version = '1.1.0'
                        else:
                            datafile = DATA_FILE
                            decision_version = '1.0.0'

                    _, protocol = self._create_mock(WireProtocolData(datafile), *args)
                    ext_handlers, _ = protocol.get_ext_handlers()
                    self.assertEqual(1, len(ext_handlers.extHandlers))
                    ext_handler = ext_handlers.extHandlers[0]
                    self.assertEqual('OSTCExtensions.ExampleHandlerLinux', ext_handler.name)
                    self.assertEqual(config_version, ext_handler.properties.version, "config version.")
                    ExtHandlerInstance(ext_handler, protocol).decide_version()
                    self.assertEqual(decision_version, ext_handler.properties.version, "decision version.")

    def test_ext_handler_version_decide_between_minor_versions(self, *args):
        """
        Using v2.x~v4.x for unit testing
        Available versions via manifest XML (I stands for internal):
        2.0.0, 2.1.0, 2.1.1, 2.2.0, 2.3.0(I), 2.4.0(I), 3.0, 3.1, 4.0.0.0, 4.0.0.1, 4.1.0.0
        """

        # (config_version, exptected_version, autoupgrade_expected_version)
        cases = [
            ('2.0',     '2.0.0',    '2.2.0'),
            ('2.0.0',   '2.0.0',    '2.2.0'),
            ('2.1.0',   '2.1.1',    '2.2.0'),
            ('2.2.0',   '2.2.0',    '2.2.0'),
            ('2.3.0',   '2.3.0',    '2.4.0'),
            ('2.4.0',   '2.4.0',    '2.4.0'),
            ('3.0',     '3.0',      '3.1'),
            ('4.0',     '4.0.0.1',  '4.1.0.0'),
        ]

        _, protocol = self._create_mock(WireProtocolData(DATA_FILE), *args)
        version_uri = Mock()
        version_uri.uri = 'http://some/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'

        for (config_version, expected_version, autoupgrade_expected_version) in cases:
            ext_handler = Mock()
            ext_handler.properties = Mock()
            ext_handler.name = 'OSTCExtensions.ExampleHandlerLinux'
            ext_handler.versionUris = [version_uri]
            ext_handler.properties.version = config_version
            ExtHandlerInstance(ext_handler, protocol).decide_version()
            self.assertEqual(expected_version, ext_handler.properties.version)

            ext_handler.properties.version = config_version
            ext_handler.properties.upgradePolicy = 'auto'
            ExtHandlerInstance(ext_handler, protocol).decide_version()
            self.assertEqual(autoupgrade_expected_version, ext_handler.properties.version)

    def test_ext_handler_version_invalid_versions(self, *args):
        cases = ['2', '2.5', '2.0.1']

        _, protocol = self._create_mock(WireProtocolData(DATA_FILE), *args)
        version_uri = Mock()
        version_uri.uri = 'http://some/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'

        for config_version in cases:
            ext_handler = Mock()
            ext_handler.properties = Mock()
            ext_handler.name = 'OSTCExtensions.ExampleHandlerLinux'
            ext_handler.versionUris = [version_uri]
            ext_handler.properties.version = config_version
            self.assertRaises(ExtensionError, ExtHandlerInstance(ext_handler, protocol).decide_version)


if __name__ == '__main__':
    unittest.main()

