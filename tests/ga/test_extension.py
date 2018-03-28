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

import glob
import os
import os.path
import shutil
import tempfile
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil

from tests.protocol.mockwiredata import *

from azurelinuxagent.common.exception import *
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.restapi import ExtHandlerStatus, \
                                                    ExtensionStatus, \
                                                    ExtensionSubStatus, \
                                                    Extension, \
                                                    VMStatus, ExtHandler, \
                                                    get_properties
from azurelinuxagent.ga.exthandlers import *
from azurelinuxagent.common.protocol.wire import WireProtocol


class TestExtensionCleanup(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.ext_handlers = ExtHandlersHandler()
        self.lib_dir = tempfile.mkdtemp()

    def _install_handlers(self, start=0, count=1,
                        handler_state=ExtHandlerState.Installed):
        src = os.path.join(data_dir, "ext", "sample_ext-1.3.0.zip")
        version = FlexibleVersion("1.3.0")
        version += start - version.patch

        for i in range(start, start+count):
            eh = ExtHandler()
            eh.name = "sample_ext"
            eh.properties.version = str(version)
            handler = ExtHandlerInstance(eh, "unused")

            dst = os.path.join(self.lib_dir,
                    handler.get_full_name()+HANDLER_PKG_EXT)
            shutil.copy(src, dst)

            if not handler_state is None:
                zipfile.ZipFile(dst).extractall(handler.get_base_dir())
                handler.set_handler_state(handler_state)

            version += 1
    
    def _count_packages(self):
        return len(glob.glob(os.path.join(self.lib_dir, "*.zip")))

    def _count_installed(self):
        paths = os.listdir(self.lib_dir)
        paths = [os.path.join(self.lib_dir, p) for p in paths]
        return len([p for p in paths
                        if os.path.isdir(p) and self._is_installed(p)])

    def _count_uninstalled(self):
        paths = os.listdir(self.lib_dir)
        paths = [os.path.join(self.lib_dir, p) for p in paths]
        return len([p for p in paths
                        if os.path.isdir(p) and not self._is_installed(p)])

    def _is_installed(self, path):
        path = os.path.join(path, 'config', 'HandlerState')
        return fileutil.read_file(path) != "NotInstalled"

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_cleanup_leaves_installed_extensions(self, mock_conf):
        mock_conf.return_value = self.lib_dir

        self._install_handlers(start=0, count=5, handler_state=ExtHandlerState.Installed)
        self._install_handlers(start=5, count=5, handler_state=ExtHandlerState.Enabled)

        self.assertEqual(self._count_packages(), 10)
        self.assertEqual(self._count_installed(), 10)

        self.ext_handlers.cleanup_outdated_handlers()

        self.assertEqual(self._count_packages(), 10)
        self.assertEqual(self._count_installed(), 10)
        self.assertEqual(self._count_uninstalled(), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_cleanup_removes_uninstalled_extensions(self, mock_conf):
        mock_conf.return_value = self.lib_dir

        self._install_handlers(start=0, count=5, handler_state=ExtHandlerState.Installed)
        self._install_handlers(start=5, count=5, handler_state=ExtHandlerState.NotInstalled)

        self.assertEqual(self._count_packages(), 10)
        self.assertEqual(self._count_installed(), 5)
        self.assertEqual(self._count_uninstalled(), 5)

        self.ext_handlers.cleanup_outdated_handlers()

        self.assertEqual(self._count_packages(), 5)
        self.assertEqual(self._count_installed(), 5)
        self.assertEqual(self._count_uninstalled(), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_cleanup_removes_orphaned_packages(self, mock_conf):
        mock_conf.return_value = self.lib_dir

        self._install_handlers(start=0, count=5, handler_state=ExtHandlerState.Installed)
        self._install_handlers(start=5, count=5, handler_state=None)

        self.assertEqual(self._count_packages(), 10)
        self.assertEqual(self._count_installed(), 5)
        self.assertEqual(self._count_uninstalled(), 0)

        self.ext_handlers.cleanup_outdated_handlers()

        self.assertEqual(self._count_packages(), 5)
        self.assertEqual(self._count_installed(), 5)
        self.assertEqual(self._count_uninstalled(), 0)


class TestHandlerStateMigration(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        handler_name = "Not.A.Real.Extension"
        handler_version = "1.2.3"

        self.ext_handler = ExtHandler(handler_name)
        self.ext_handler.properties.version = handler_version
        self.ext_handler_i = ExtHandlerInstance(self.ext_handler, "dummy protocol")

        self.handler_state = "Enabled"
        self.handler_status = ExtHandlerStatus(
            name=handler_name,
            version=handler_version,
            status="Ready",
            message="Uninteresting message")
        return

    def _prepare_handler_state(self):
        handler_state_path = os.path.join(
                                self.tmp_dir,
                                "handler_state",
                                self.ext_handler_i.get_full_name())
        os.makedirs(handler_state_path)
        fileutil.write_file(
            os.path.join(handler_state_path, "state"),
            self.handler_state)
        fileutil.write_file(
            os.path.join(handler_state_path, "status"),
            json.dumps(get_properties(self.handler_status)))
        return

    def _prepare_handler_config(self):
        handler_config_path = os.path.join(
                                self.tmp_dir,
                                self.ext_handler_i.get_full_name(),
                                "config")
        os.makedirs(handler_config_path)
        return

    def test_migration_migrates(self):
        self._prepare_handler_state()
        self._prepare_handler_config()

        migrate_handler_state()

        self.assertEquals(self.ext_handler_i.get_handler_state(), self.handler_state)
        self.assertEquals(
            self.ext_handler_i.get_handler_status().status,
            self.handler_status.status)
        return

    def test_migration_skips_if_empty(self):
        self._prepare_handler_config()

        migrate_handler_state()

        self.assertFalse(
            os.path.isfile(os.path.join(self.ext_handler_i.get_conf_dir(), "HandlerState")))
        self.assertFalse(
            os.path.isfile(os.path.join(self.ext_handler_i.get_conf_dir(), "HandlerStatus")))
        return

    def test_migration_cleans_up(self):
        self._prepare_handler_state()
        self._prepare_handler_config()

        migrate_handler_state()

        self.assertFalse(os.path.isdir(os.path.join(conf.get_lib_dir(), "handler_state")))
        return

    def test_migration_does_not_overwrite(self):
        self._prepare_handler_state()
        self._prepare_handler_config()

        state = "Installed"
        status = "NotReady"
        code = 1
        message = "A message"
        self.assertNotEquals(state, self.handler_state)
        self.assertNotEquals(status, self.handler_status.status)
        self.assertNotEquals(code, self.handler_status.code)
        self.assertNotEquals(message, self.handler_status.message)

        self.ext_handler_i.set_handler_state(state)
        self.ext_handler_i.set_handler_status(status=status, code=code, message=message)

        migrate_handler_state()

        self.assertEquals(self.ext_handler_i.get_handler_state(), state)
        handler_status = self.ext_handler_i.get_handler_status()
        self.assertEquals(handler_status.status, status)
        self.assertEquals(handler_status.code, code)
        self.assertEquals(handler_status.message, message)
        return

    @patch("shutil.move", side_effect=Exception)
    def test_migration_ignores_move_errors(self, shutil_mock):
        self._prepare_handler_state()
        self._prepare_handler_config()

        try:
            migrate_handler_state()
        except Exception as e:
            self.assertTrue(False, "Unexpected exception: {0}".format(str(e)))
        return

    @patch("shutil.rmtree", side_effect=Exception)
    def test_migration_ignores_tree_remove_errors(self, shutil_mock):
        self._prepare_handler_state()
        self._prepare_handler_config()

        try:
            migrate_handler_state()
        except Exception as e:
            self.assertTrue(False, "Unexpected exception: {0}".format(str(e)))
        return


@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtension(AgentTestCase):

    def _assert_handler_status(self, report_vm_status, expected_status, 
                               expected_ext_count, version,
                               expected_handler_name="OSTCExtensions.ExampleHandlerLinux"):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertNotEquals(0, len(vm_status.vmAgent.extensionHandlers))
        handler_status = vm_status.vmAgent.extensionHandlers[0]
        self.assertEquals(expected_status, handler_status.status)
        self.assertEquals(expected_handler_name,
                          handler_status.name)
        self.assertEquals(version, handler_status.version)
        self.assertEquals(expected_ext_count, len(handler_status.extensions))
        return
    
    def _assert_no_handler_status(self, report_vm_status):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertEquals(0, len(vm_status.vmAgent.extensionHandlers))
        return

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil):
        """Test enable/disable/uninstall of an extension"""
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
        
        #Test hotfix
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"", 
                                                        "seqNo=\"2\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        #Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.0", "1.2.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"2\"",
                                                        "seqNo=\"3\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        #Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 
                                    1, "1.2.0")

        #Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        #Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
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
    
    def test_ext_handler_sequencing(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        #Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # check handler list
        self.assertTrue(exthandlers_handler.ext_handlers is not None)
        self.assertTrue(exthandlers_handler.ext_handlers.extHandlers is not None)
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.dependencyLevel, 1)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.dependencyLevel, 2)

        #Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        #Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"",
                                                        "dependencyLevel=\"3\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"",
                                                        "dependencyLevel=\"4\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.dependencyLevel, 3)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.dependencyLevel, 4)

        #Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.dependencyLevel, 4)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.dependencyLevel, 3)

        #Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"3\"",
                                                        "dependencyLevel=\"6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"4\"",
                                                        "dependencyLevel=\"5\"")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.dependencyLevel, 6)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.dependencyLevel, 5)

    def test_ext_handler_rollingupgrade(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_ROLLINGUPGRADE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        #Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        #Test goal state changed without new GUID
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test GUID change without new version available
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("FE0987654321", "FE0987654322")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test hotfix available without GUID change
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test GUID change with hotfix
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("FE0987654322", "FE0987654323")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.1.1")

        #Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        #Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>7<",
                                                            "<Incarnation>8<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        #Test re-install
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>8<",
                                                            "<Incarnation>9<")
        test_data.ext_conf = test_data.ext_conf.replace("uninstall", "enabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test upgrade available without GUID change
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>9<",
                                                            "<Incarnation>10<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.0", "1.2.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        #Test GUID change with upgrade available
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>10<",
                                                            "<Incarnation>11<")
        test_data.ext_conf = test_data.ext_conf.replace("FE0987654323", "FE0987654324")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

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

    def test_handle_ext_handlers_on_hold_true(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, exthandlers_handler.last_etag = protocol.get_ext_handlers()
        protocol.get_artifacts_profile = MagicMock()
        exthandlers_handler.protocol = protocol

        # Disable extension handling blocking
        conf.get_enable_overprovisioning = Mock(return_value=False)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            patch_handle_ext_handler.assert_called()

        # enable extension handling blocking
        conf.get_enable_overprovisioning = Mock(return_value=True)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            patch_handle_ext_handler.assert_not_called()


    def test_handle_ext_handlers_on_hold_false(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, exthandlers_handler.last_etag = protocol.get_ext_handlers()
        exthandlers_handler.protocol = protocol

        # enable extension handling blocking
        conf.get_enable_overprovisioning = Mock(return_value=True)

        #Test when is_on_hold returns False
        from azurelinuxagent.common.protocol.wire import InVMArtifactsProfile
        mock_in_vm_artifacts_profile = InVMArtifactsProfile(MagicMock())
        mock_in_vm_artifacts_profile.is_on_hold = Mock(return_value=False)
        protocol.get_artifacts_profile = Mock(return_value=mock_in_vm_artifacts_profile)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            patch_handle_ext_handler.assert_called_once()

        #Test when in_vm_artifacts_profile is not available
        protocol.get_artifacts_profile = Mock(return_value=None)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            patch_handle_ext_handler.assert_called_once()

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
                if internal:
                    config_version = '1.3.0'
                    decision_version = '1.3.0'
                    if autoupgrade:
                        datafile = DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION
                    else:
                        datafile = DATA_FILE_EXT_INTERNALVERSION
                else:
                    config_version = '1.0.0'
                    if autoupgrade:
                        datafile = DATA_FILE_EXT_AUTOUPGRADE
                        decision_version = '1.2.0'
                    else:
                        datafile = DATA_FILE
                        decision_version = '1.0.0'

                _, protocol = self._create_mock(WireProtocolData(datafile), *args)
                ext_handlers, etag = protocol.get_ext_handlers()
                self.assertEqual(1, len(ext_handlers.extHandlers))
                ext_handler = ext_handlers.extHandlers[0]
                self.assertEqual('OSTCExtensions.ExampleHandlerLinux', ext_handler.name)
                self.assertEqual(config_version, ext_handler.properties.version, "config version.")
                ExtHandlerInstance(ext_handler, protocol).decide_version(etag)
                self.assertEqual(decision_version, ext_handler.properties.version, "decision version.")

    def test_ext_handler_version_decide_between_minor_versions(self, *args):
        """
        Using v2.x~v4.x for unit testing
        Available versions via manifest XML (I stands for internal):
        2.0.0, 2.1.0, 2.1.1, 2.2.0, 2.3.0(I), 2.4.0(I), 3.0, 3.1, 4.0.0.0, 4.0.0.1, 4.1.0.0
        See tests/data/wire/manifest.xml for possible versions
        """

        # (installed_version, config_version, exptected_version, autoupgrade_expected_version)
        cases = [
            (None,  '2.0',     '2.0.0',    '2.2.0'),
            (None,  '2.0.0',   '2.0.0',    '2.2.0'),
            ('1.0', '1.0.0',   '1.0.0',    '1.2.0'),
            (None,  '2.1.0',   '2.1.1',    '2.2.0'),
            (None,  '2.2.0',   '2.2.0',    '2.2.0'),
            (None,  '2.3.0',   '2.3.0',    '2.3.0'),
            (None,  '2.4.0',   '2.4.0',    '2.4.0'),
            (None,  '3.0',     '3.0',      '3.1'),
            (None,  '4.0',     '4.0.0.1',  '4.1.0.0'),
        ]

        _, protocol = self._create_mock(WireProtocolData(DATA_FILE), *args)
        version_uri = Mock()
        version_uri.uri = 'http://some/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'
        incarnation = 1

        for (installed_version, config_version, expected_version, autoupgrade_expected_version) in cases:
            ext_handler = Mock()
            ext_handler.properties = Mock()
            ext_handler.name = 'OSTCExtensions.ExampleHandlerLinux'
            ext_handler.versionUris = [version_uri]
            ext_handler.properties.version = config_version
            
            ext_handler_instance = ExtHandlerInstance(ext_handler, protocol)
            ext_handler_instance.get_installed_version = Mock(return_value=installed_version)

            ext_handler_instance.decide_version(incarnation)
            self.assertEqual(expected_version, ext_handler.properties.version)
            incarnation += 1

            ext_handler.properties.version = config_version
            ext_handler.properties.upgradePolicy = 'auto'

            ext_handler_instance = ExtHandlerInstance(ext_handler, protocol)
            ext_handler_instance.get_installed_version = Mock(return_value=installed_version)

            ext_handler_instance.decide_version(incarnation)
            self.assertEqual(autoupgrade_expected_version, ext_handler.properties.version)
            incarnation += 1


OS_PATH_EXISTS = os.path.exists


@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionEnable(AgentTestCase):
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
        return

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil):
        """Test enable/disable/uninstall of an extension"""
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


    @staticmethod
    def _settings_file_does_not_exist(*args, **kwargs):
        if args[0].endswith(".settings"):
            return False
        else:
            return OS_PATH_EXISTS(args[0])

    @staticmethod
    def _settings_file_does_exist(*args, **kwargs):
        if args[0].endswith(".settings"):
            return True
        else:
            return OS_PATH_EXISTS(args[0])

    def test_global_enabled_forced_should_be_true_after_first_run(self, *args):
        """
        ExtHandlersHandler starts with the condition that it should force all extensions
        to be enabled regardless if there is a new settings document or not.  After the
        first "run" extensions are no longer forced. This test verifies those two truths.
        """
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        self.assertEqual(False, exthandlers_handler._global_enabled_forced)
        exthandlers_handler.run()
        self.assertEqual(True, exthandlers_handler._global_enabled_forced)

    @patch('os.path.exists')
    def test_enable_on_agent_restart(self, mock_exists, *args):
        """
        ExtensionHandlersHandler should always call enable on agent (re)start.
        """
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Even though the settings file already exists enable is still called because this
        # is an agent restart.
        mock_exists.side_effect = self._settings_file_does_exist
        exthandlers_handler.last_etag = "--unit-test--00"
        with patch.object(ExtHandlerInstance, 'enable') as ext_handler_i:
            exthandlers_handler.run()
            self.assertEqual(1, ext_handler_i.call_count)

    @patch('os.path.exists')
    def test_enable_new_settings_only(self, mock_exists, *args):
        """
        ExtensionHandlersHandler should only enable an extension if the settings
        document does not exists.
        """
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        # Set the value to False, which tells ExtensionHandlersHandler that this is
        # not an agent restart.  An agent restarts forces an enable to happen for
        # all extensions.
        exthandlers_handler._global_enabled_forced = False


        # Setup an enable for the first settings.  This settings has not been executed
        # and must be enabled.
        mock_exists.side_effect = self._settings_file_does_not_exist
        exthandlers_handler.last_etag = "--unit-test--00"
        with patch.object(ExtHandlerInstance, 'enable') as ext_handler_i:
            exthandlers_handler.run()
            self.assertEqual(1, ext_handler_i.call_count)

        # Execute an enable again.  This shoiuld not be executed, but the same settings
        # document is being used.
        #
        # The ETag must be updated else we will not even get to enable in the first place.
        mock_exists.side_effect = self._settings_file_does_exist
        exthandlers_handler.last_etag = "--unit-test--01"
        with patch.object(ExtHandlerInstance, 'enable') as ext_handler_i:
            exthandlers_handler.run()
            self.assertEqual(0, ext_handler_i.call_count)
            ext_handler_i.assert_not_called()

        # Execute an enable again, but update the settings.  The extension should be
        # enabled as a result of updating the setttings.
        #
        # The ETag must be updated else we will not even get to enable in the first place.
        mock_exists.side_effect = self._settings_file_does_not_exist
        exthandlers_handler.last_etag = "--unit-test--02"
        with patch.object(ExtHandlerInstance, 'enable') as ext_handler_i:
            exthandlers_handler.run()
            self.assertEqual(1, ext_handler_i.call_count)


if __name__ == '__main__':
    unittest.main()

