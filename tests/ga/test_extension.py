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

import os.path

from datetime import timedelta

from azurelinuxagent.ga.monitor import get_monitor_handler
from nose.plugins.attrib import attr
from tests.protocol.mockwiredata import *

from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerProperties
from azurelinuxagent.ga.exthandlers import *
from azurelinuxagent.common.protocol.wire import WireProtocol, InVMArtifactsProfile

# Mocking the original sleep to reduce test execution time
SLEEP = time.sleep


def mock_sleep(sec=0.01):
    SLEEP(sec)


def do_not_run_test():
    return True


def raise_system_exception():
    raise Exception


def raise_ioerror(*args):
    e = IOError()
    from errno import EIO
    e.errno = EIO
    raise e


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

        for i in range(start, start + count):
            eh = ExtHandler()
            eh.name = "sample_ext"
            eh.properties.version = str(version)
            handler = ExtHandlerInstance(eh, "unused")

            dst = os.path.join(self.lib_dir,
                               handler.get_full_name() + HANDLER_PKG_EXT)
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

    def test_set_handler_status_ignores_none_content(self):
        """
        Validate that set_handler_status ignore cases where json.dumps
        returns a value of None.
        """
        self._prepare_handler_state()
        self._prepare_handler_config()

        status = "Ready"
        code = 0
        message = "A message"

        try:
            with patch('json.dumps', return_value=None):
                self.ext_handler_i.set_handler_status(status=status, code=code, message=message)
        except Exception as e:
            self.fail("set_handler_status threw an exception")

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


class ExtensionTestCase(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        cls.cgroups_enabled = CGroupConfigurator.get_instance().enabled()
        CGroupConfigurator.get_instance().disable()

    @classmethod
    def tearDownClass(cls):
        if cls.cgroups_enabled:
            CGroupConfigurator.get_instance().enable()
        else:
            CGroupConfigurator.get_instance().disable()


@patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtension(ExtensionTestCase):

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

    def _assert_ext_pkg_file_status(self, expected_to_be_present=True, extension_version="1.0.0",
                                    extension_handler_name="OSTCExtensions.ExampleHandlerLinux"):
        zip_file_format = "{0}__{1}.zip"
        if expected_to_be_present:
            self.assertIn(zip_file_format.format(extension_handler_name, extension_version), os.listdir(conf.get_lib_dir()))
        else:
            self.assertNotIn(zip_file_format.format(extension_handler_name, extension_version), os.listdir(conf.get_lib_dir()))

    def _assert_no_handler_status(self, report_vm_status):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertEquals(0, len(vm_status.vmAgent.extensionHandlers))
        return

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil, *args):
        """Test enable/disable/uninstall of an extension"""
        handler = get_exthandlers_handler()

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        handler.protocol_util.get_protocol = Mock(return_value=protocol)
        return handler, protocol

    def _set_up_update_test_and_update_gs(self, patch_command, *args):
        """
        This helper function sets up the Update test by setting up the protocol and ext_handler and asserts the
        ext_handler runs fine the first time before patching a failure command for testing.
        :param patch_command: The patch_command to setup for failure
        :param args: Any additional args passed to the function, needed for creating a mock for handler and protocol
        :return: test_data, exthandlers_handler, protocol
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()

        self.assertEqual(0, patch_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Ensure the patched command fails
        patch_command.return_value = "exit 1"

        return test_data, exthandlers_handler, protocol

    def test_ext_handler(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.1")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"",
                                                        "seqNo=\"2\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.1", "1.2.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"2\"",
                                                        "seqNo=\"3\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.2.0")

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_zip_file_packages_removed_in_update_case(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.0.0")

        # Update the package
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version="1.0.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.1.0")

        # Update the package second time
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"",
                                                        "seqNo=\"2\"")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.0", "1.2.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version="1.1.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.2.0")

    def test_ext_zip_file_packages_removed_in_uninstall_case(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        extension_version = "1.0.0"

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, extension_version)
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version=extension_version)

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version=extension_version)

    def test_ext_zip_file_packages_removed_in_update_and_uninstall_case(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.0.0")

        # Update the package
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version="1.0.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.1.0")

        # Update the package second time
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"",
                                                        "seqNo=\"2\"")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.0", "1.2.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version="1.1.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True,
                                         extension_version="1.2.0")

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
        self._assert_ext_pkg_file_status(expected_to_be_present=False,
                                         extension_version="1.2.0")

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

        # Assert no extension handler status
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_handler_sequencing(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # check handler list
        self.assertTrue(exthandlers_handler.ext_handlers is not None)
        self.assertTrue(exthandlers_handler.ext_handlers.extHandlers is not None)
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 1)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 2)

        # Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        # Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        # Swap the dependency ordering
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"",
                                                        "dependencyLevel=\"3\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"",
                                                        "dependencyLevel=\"4\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 3)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 4)

        # Test disable
        # In the case of disable, the last extension to be enabled should be
        # the first extension disabled. The first extension enabled should be
        # the last one disabled.
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 4)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 3)

        # Test uninstall
        # In the case of uninstall, the last extension to be installed should be
        # the first extension uninstalled. The first extension installed
        # should be the last one uninstalled.
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        # Swap the dependency ordering AGAIN
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"3\"",
                                                        "dependencyLevel=\"6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"4\"",
                                                        "dependencyLevel=\"5\"")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 6)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 5)

    def test_ext_handler_sequencing_default_dependency_level(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)

    def test_ext_handler_sequencing_invalid_dependency_level(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"",
                                                        "dependencyLevel=\"a6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"",
                                                        "dependencyLevel=\"5b\"")
        exthandlers_handler.run()

        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)

    @patch('time.gmtime', MagicMock(return_value=time.gmtime(0)))
    def test_ext_handler_reporting_status_file(self, *args):
        expected_status = '''
{{
    "agent_name": "{agent_name}",
    "current_version": "{current_version}",
    "goal_state_version": "{goal_state_version}",
    "distro_details": "{distro_details}",
    "last_successful_status_upload_time": "{last_successful_status_upload_time}",
    "python_version": "{python_version}",
    "extensions_status": [
        {{
            "name": "OSTCExtensions.ExampleHandlerLinux",
            "version": "1.0.0",
            "status": "Ready"
        }},
        {{
            "name": "Microsoft.Powershell.ExampleExtension",
            "version": "1.0.0",
            "status": "Ready"
        }},
        {{
            "name": "Microsoft.EnterpriseCloud.Monitoring.ExampleHandlerLinux",
            "version": "1.0.0",
            "status": "Ready"
        }},
        {{
            "name": "Microsoft.CPlat.Core.ExampleExtensionLinux",
            "version": "1.0.0",
            "status": "Ready"
        }},
        {{
            "name": "Microsoft.OSTCExtensions.Edp.ExampleExtensionLinuxInTest",
            "version": "1.0.0",
            "status": "Ready"
        }}
    ]
}}'''.format(agent_name=AGENT_NAME,
             current_version=str(CURRENT_VERSION),
             goal_state_version=str(GOAL_STATE_AGENT_VERSION),
             distro_details="{0}:{1}".format(DISTRO_NAME, DISTRO_VERSION),
             last_successful_status_upload_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             python_version="Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO))

        expected_status_json = json.loads(expected_status)

        test_data = WireProtocolData(DATA_FILE_MULTIPLE_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()

        status_path = os.path.join(conf.get_lib_dir(), AGENT_STATUS_FILE)
        actual_status_json = json.loads(fileutil.read_file(status_path))

        self.assertEquals(expected_status_json, actual_status_json)

    def test_ext_handler_rollingupgrade(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_ROLLINGUPGRADE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test minor version bump
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test hotfix version bump
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.0", "1.1.1")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.1.1")

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # Test re-install
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>7<",
                                                            "<Incarnation>8<")
        test_data.ext_conf = test_data.ext_conf.replace("uninstall", "enabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test version bump post-re-install
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>8<",
                                                            "<Incarnation>9<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.1", "1.2.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test rollback
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>9<",
                                                            "<Incarnation>10<")
        test_data.ext_conf = test_data.ext_conf.replace("1.2.0", "1.1.0")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_download_failure_transient(self, mock_add_event, *args):
        original_sleep = time.sleep

        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.download_ext_handler_pkg = Mock(side_effect=ProtocolError)

        exthandlers_handler.run()

        self.assertEquals(0, mock_add_event.call_count)

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_report_status_permanent(self, mock_add_event, mock_error_state, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.report_vm_status = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True
        exthandlers_handler.run()
        self.assertEquals(5, mock_add_event.call_count)
        args, kw = mock_add_event.call_args
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("Failed to report vm agent status" in kw['message'])
        self.assertEquals("ReportStatusExtended", kw['op'])

    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_report_status_resource_gone(self, mock_add_event, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.report_vm_status = Mock(side_effect=ResourceGoneError)

        exthandlers_handler.run()
        self.assertEquals(4, mock_add_event.call_count)
        args, kw = mock_add_event.call_args
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("ResourceGoneError" in kw['message'])
        self.assertEquals("ExtensionProcessing", kw['op'])

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.report_event')
    def test_ext_handler_download_failure_permanent_ProtocolError(self, mock_add_event, mock_error_state, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.get_ext_handler_pkgs = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True

        exthandlers_handler.run()

        self.assertEquals(1, mock_add_event.call_count)
        args, kw = mock_add_event.call_args_list[0]
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("Failed to get ext handler pkgs" in kw['message'])
        self.assertTrue("ProtocolError" in kw['message'])

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.common.event.add_event')
    def test_ext_handler_download_failure_permanent_with_ExtensionDownloadError_and_triggered(self, mock_add_event,
                                                                                              mock_error_state, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.get_ext_handler_pkgs = Mock(side_effect=ExtensionDownloadError)

        mock_error_state.return_value = True

        exthandlers_handler.run()

        self.assertEquals(1, mock_add_event.call_count)
        args, kw = mock_add_event.call_args_list[0]
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("Failed to get artifact for over" in kw['message'])
        self.assertTrue("ExtensionDownloadError" in kw['message'])
        self.assertEquals("Download", kw['op'])

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.common.event.add_event')
    def test_ext_handler_download_failure_permanent_with_ExtensionDownloadError_and_not_triggered(self, mock_add_event,
                                                                                                  mock_error_state,
                                                                                                  *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.get_ext_handler_pkgs = Mock(side_effect=ExtensionDownloadError)

        mock_error_state.return_value = False

        exthandlers_handler.run()

        self.assertEquals(0, mock_add_event.call_count)

    @patch('azurelinuxagent.ga.exthandlers.fileutil')
    def test_ext_handler_io_error(self, mock_fileutil, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        mock_fileutil.write_file.return_value = IOError("Mock IO Error")
        exthandlers_handler.run()

    def test_extension_processing_allowed(self, *args):
        exthandlers_handler = get_exthandlers_handler()
        exthandlers_handler.protocol = Mock()

        # disable extension handling in configuration
        with patch.object(conf, 'get_extensions_enabled', return_value=False):
            self.assertFalse(exthandlers_handler.extension_processing_allowed())

        # enable extension handling in configuration
        with patch.object(conf, "get_extensions_enabled", return_value=True):
            # disable overprovisioning in configuration
            with patch.object(conf, 'get_enable_overprovisioning', return_value=False):
                self.assertTrue(exthandlers_handler.extension_processing_allowed())

            # enable overprovisioning in configuration
            with patch.object(conf, "get_enable_overprovisioning", return_value=True):
                # disable protocol support for over-provisioning
                with patch.object(exthandlers_handler.protocol, 'supports_overprovisioning', return_value=False):
                    self.assertTrue(exthandlers_handler.extension_processing_allowed())

                # enable protocol support for over-provisioning
                with patch.object(exthandlers_handler.protocol, "supports_overprovisioning", return_value=True):
                    with patch.object(exthandlers_handler.protocol.get_artifacts_profile(), "is_on_hold",
                                      side_effect=[True, False]):
                        # Enable on_hold property in artifact_blob
                        self.assertFalse(exthandlers_handler.extension_processing_allowed())

                        # Disable on_hold property in artifact_blob
                        self.assertTrue(exthandlers_handler.extension_processing_allowed())

    def test_handle_ext_handlers_on_hold_true(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, exthandlers_handler.last_etag = protocol.get_ext_handlers()
        protocol.get_artifacts_profile = MagicMock()
        exthandlers_handler.protocol = protocol

        # Disable extension handling blocking
        exthandlers_handler.extension_processing_allowed = Mock(return_value=False)
        with patch.object(ExtHandlersHandler, 'handle_ext_handlers') as patch_handle_ext_handlers:
            exthandlers_handler.run()
            self.assertEqual(0, patch_handle_ext_handlers.call_count)

        # enable extension handling blocking
        exthandlers_handler.extension_processing_allowed = Mock(return_value=True)
        with patch.object(ExtHandlersHandler, 'handle_ext_handlers') as patch_handle_ext_handlers:
            exthandlers_handler.run()
            self.assertEqual(1, patch_handle_ext_handlers.call_count)

    def test_handle_ext_handlers_on_hold_false(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, exthandlers_handler.last_etag = protocol.get_ext_handlers()
        exthandlers_handler.protocol = protocol

        # enable extension handling blocking
        conf.get_enable_overprovisioning = Mock(return_value=True)

        # Test when is_on_hold returns False
        from azurelinuxagent.common.protocol.wire import InVMArtifactsProfile
        mock_in_vm_artifacts_profile = InVMArtifactsProfile(MagicMock())
        mock_in_vm_artifacts_profile.is_on_hold = Mock(return_value=False)
        protocol.get_artifacts_profile = Mock(return_value=mock_in_vm_artifacts_profile)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            self.assertEqual(1, patch_handle_ext_handler.call_count)

        # Test when in_vm_artifacts_profile is not available
        protocol.get_artifacts_profile = Mock(return_value=None)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            self.assertEqual(1, patch_handle_ext_handler.call_count)

    def test_last_etag_on_extension_processing(self, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, etag = protocol.get_ext_handlers()
        exthandlers_handler.protocol = protocol

        # Disable extension handling blocking in the first run and enable in the 2nd run
        with patch.object(exthandlers_handler, 'extension_processing_allowed', side_effect=[False, True]):
            exthandlers_handler.run()
            self.assertIsNone(exthandlers_handler.last_etag,
                              "The last etag should be None initially as extension_processing is False")
            self.assertNotEqual(etag, exthandlers_handler.last_etag,
                                "Last etag and etag should not be same if extension processing is disabled")
            exthandlers_handler.run()
            self.assertIsNotNone(exthandlers_handler.last_etag,
                                 "Last etag should not be none if extension processing is allowed")
            self.assertEqual(etag, exthandlers_handler.last_etag,
                             "Last etag and etag should be same if extension processing is enabled")

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

        # Remove status file and re-run collecting extension status
        status_file = os.path.join(self.tmp_dir,
                                   "OSTCExtensions.ExampleHandlerLinux-1.0.0",
                                   "status", "0.status")
        self.assertTrue(os.path.isfile(status_file))
        os.remove(status_file)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "error", 0)

    def test_wait_for_handler_successful_completion_empty_exts(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is no extension in a handler.
        Expected to return True.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        handler = ExtHandler(name="handler")

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=None)
        self.assertTrue(exthandlers_handler.wait_for_handler_successful_completion(handler, datetime.datetime.utcnow()))

    def _helper_wait_for_handler_successful_completion(self, exthandlers_handler):
        '''
        Call wait_for_handler_successful_completion() passing a handler with an extension.
        Override the wait time to be 5 seconds to minimize the timout duration.
        Return the value returned by wait_for_handler_successful_completion().
        '''
        handler_name = "Handler"
        exthandler = ExtHandler(name=handler_name)
        extension = Extension(name=handler_name)
        exthandler.properties.extensions.append(extension)

        # Override the timeout value to minimize the test duration
        wait_until = datetime.datetime.utcnow() + datetime.timedelta(seconds=0.1)
        return exthandlers_handler.wait_for_handler_successful_completion(exthandler, wait_until)

    def test_wait_for_handler_successful_completion_no_status(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is no status file or seq_no is negative.
        Expected to return False.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=None)
        self.assertFalse(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_success_status(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is successful status.
        Expected to return True.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        status = "success"

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=status)
        self.assertTrue(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_error_status(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is error status.
        Expected to return False.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        status = "error"

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=status)
        self.assertFalse(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_timeout(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is non terminal status.
        Expected to return False.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Choose a non-terminal status
        status = "warning"

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=status)
        self.assertFalse(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_get_ext_handling_status(self, *args):
        '''
        Testing get_ext_handling_status() function with various cases and
        verifying against the expected values
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        handler_name = "Handler"
        exthandler = ExtHandler(name=handler_name)
        extension = Extension(name=handler_name)
        exthandler.properties.extensions.append(extension)

        # In the following list of test cases, the first element corresponds to seq_no.
        # the second element is the status file name, the third element indicates if the status file exits or not.
        # The fourth element is the expected value from get_ext_handling_status()
        test_cases = [
            [-5, None, False, None],
            [-1, None, False, None],
            [0, None, False, None],
            [0, "filename", False, "warning"],
            [0, "filename", True, ExtensionStatus(status="success")],
            [5, "filename", False, "warning"],
            [5, "filename", True, ExtensionStatus(status="success")]
        ]

        orig_state = os.path.exists
        for case in test_cases:
            ext_handler_i = ExtHandlerInstance(exthandler, protocol)
            ext_handler_i.get_status_file_path = MagicMock(return_value=(case[0], case[1]))
            os.path.exists = MagicMock(return_value=case[2])
            if case[2]:
                # when the status file exists, it is expected return the value from collect_ext_status()
                ext_handler_i.collect_ext_status = MagicMock(return_value=case[3])

            status = ext_handler_i.get_ext_handling_status(extension)
            if case[2]:
                self.assertEqual(status, case[3].status)
            else:
                self.assertEqual(status, case[3])

        os.path.exists = orig_state

    def test_is_ext_handling_complete(self, *args):
        '''
        Testing is_ext_handling_complete() with various input and
        verifying against the expected output values.
        '''
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        handler_name = "Handler"
        exthandler = ExtHandler(name=handler_name)
        extension = Extension(name=handler_name)
        exthandler.properties.extensions.append(extension)

        ext_handler_i = ExtHandlerInstance(exthandler, protocol)

        # Testing no status case
        ext_handler_i.get_ext_handling_status = MagicMock(return_value=None)
        completed, status = ext_handler_i.is_ext_handling_complete(extension)
        self.assertTrue(completed)
        self.assertEqual(status, None)

        # Here the key represents the possible input value to is_ext_handling_complete()
        # the value represents the output tuple from is_ext_handling_complete()
        expected_results = {
            "error": (True, "error"),
            "success": (True, "success"),
            "warning": (False, "warning"),
            "transitioning": (False, "transitioning")
        }

        for key in expected_results.keys():
            ext_handler_i.get_ext_handling_status = MagicMock(return_value=key)
            completed, status = ext_handler_i.is_ext_handling_complete(extension)
            self.assertEqual(completed, expected_results[key][0])
            self.assertEqual(status, expected_results[key][1])

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
                    decision_version = '1.0.0'
                    if autoupgrade:
                        datafile = DATA_FILE_EXT_AUTOUPGRADE
                    else:
                        datafile = DATA_FILE

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
        See tests/data/wire/manifest.xml for possible versions
        """

        # (installed_version, config_version, exptected_version, autoupgrade_expected_version)
        cases = [
            (None, '2.0', '2.0.0'),
            (None, '2.0.0', '2.0.0'),
            ('1.0', '1.0.0', '1.0.0'),
            (None, '2.1.0', '2.1.0'),
            (None, '2.1.1', '2.1.1'),
            (None, '2.2.0', '2.2.0'),
            (None, '2.3.0', '2.3.0'),
            (None, '2.4.0', '2.4.0'),
            (None, '3.0', '3.0'),
            (None, '3.1', '3.1'),
            (None, '4.0', '4.0.0.1'),
            (None, '4.1', '4.1.0.0'),
        ]

        _, protocol = self._create_mock(WireProtocolData(DATA_FILE), *args)
        version_uri = Mock()
        version_uri.uri = 'http://some/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'

        for (installed_version, config_version, expected_version) in cases:
            ext_handler = Mock()
            ext_handler.properties = Mock()
            ext_handler.name = 'OSTCExtensions.ExampleHandlerLinux'
            ext_handler.versionUris = [version_uri]
            ext_handler.properties.version = config_version

            ext_handler_instance = ExtHandlerInstance(ext_handler, protocol)
            ext_handler_instance.get_installed_version = Mock(return_value=installed_version)

            ext_handler_instance.decide_version()
            self.assertEqual(expected_version, ext_handler.properties.version)

    @patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False)
    def test_extensions_disabled(self, _, *args):
        # test status is reported for no extensions
        test_data = WireProtocolData(DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # test status is reported, but extensions are not processed
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_extensions_deleted(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_DELETION)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial enable is successful
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Update incarnation, simulate new extension version and old one deleted
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"',
                                                        'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Ensure new extension can be enabled
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.install', side_effect=ExtHandlerInstance.install,
           autospec=True)
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_install_command')
    def test_install_failure(self, patch_get_install_command, patch_install, *args):
        """
        When extension install fails, the operation should not be retried.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install is unsuccessful
        patch_get_install_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(1, patch_install.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.0")

        # Ensure subsequent no further retries are made
        exthandlers_handler.run()
        self.assertEqual(1, patch_install.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_install_command')
    def test_install_failure_check_exception_handling(self, patch_get_install_command, patch_handle_ext_handler_error,
                                                      *args):
        """
        When extension install fails, the operation should be reported to our telemetry service.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure install is unsuccessful
        patch_get_install_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(1, protocol.report_vm_status.call_count)
        self.assertEqual(1, patch_handle_ext_handler_error.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command')
    def test_enable_failure(self, patch_get_enable_command, *args):
        """
        When extension enable fails, the operation should not be retried.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install is successful, but enable fails
        patch_get_enable_command.call_count = 0
        patch_get_enable_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(1, patch_get_enable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.0")

        exthandlers_handler.run()
        self.assertEqual(1, patch_get_enable_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command')
    def test_enable_failure_check_exception_handling(self, patch_get_enable_command,
                                                     patch_handle_ext_handler_error, *args):
        """
        When extension enable fails, the operation should be reported.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install is successful, but enable fails
        patch_get_enable_command.call_count = 0
        patch_get_enable_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(1, patch_get_enable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self.assertEqual(1, patch_handle_ext_handler_error.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_disable_failure(self, patch_get_disable_command, *args):
        """
        When extension disable fails, the operation should not be retried.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful, but disable fails
        patch_get_disable_command.call_count = 0
        patch_get_disable_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")

        exthandlers_handler.run()
        self.assertEqual(1, patch_get_disable_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.0")

        # Ensure there are no further retries
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_disable_command.call_count)
        self.assertEqual(3, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_disable_failure_with_exception_handling(self, patch_get_disable_command,
                                                     patch_handle_ext_handler_error, *args):
        """
        When extension disable fails, the operation should be reported.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful, but disable fails
        patch_get_disable_command.call_count = 0
        patch_get_disable_command.return_value = "exit 1"
        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")

        exthandlers_handler.run()

        self.assertEqual(1, patch_get_disable_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self.assertEqual(1, patch_handle_ext_handler_error.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_uninstall_failure(self, patch_get_uninstall_command, *args):
        """
        When extension uninstall fails, the operation should not be retried.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful, but uninstall fails
        patch_get_uninstall_command.call_count = 0
        patch_get_uninstall_command.return_value = "exit 1"
        exthandlers_handler.run()

        self.assertEqual(0, patch_get_uninstall_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "uninstall")

        exthandlers_handler.run()
        self.assertEqual(1, patch_get_uninstall_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self.assertEquals("Ready", protocol.report_vm_status.call_args[0][0].vmAgent.status)
        self._assert_no_handler_status(protocol.report_vm_status)

        # Ensure there are no further retries
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_uninstall_command.call_count)
        self.assertEqual(3, protocol.report_vm_status.call_count)
        self.assertEquals("Ready", protocol.report_vm_status.call_args[0][0].vmAgent.status)
        self._assert_no_handler_status(protocol.report_vm_status)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_update_command')
    def test_upgrade_failure(self, patch_get_update_command, *args):
        """
        Extension upgrade failure should not be retried
        """
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_update_command,
                                                                                          *args)

        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)

        # On the next iteration, update should not be retried
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)

        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails(self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
            exthandlers_handler.run()

            # When the previous version's disable fails, we expect the upgrade scenario to fail, so the enable
            # for the new version is not called and the new version handler's status is reported as not ready.
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

            # Ensure we are processing the same goal state only once
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails_and_recovers_on_next_incarnation(self, patch_get_disable_command,
                                                                                                         *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
            exthandlers_handler.run()

            # When the previous version's disable fails, we expect the upgrade scenario to fail, so the enable
            # for the new version is not called and the new version handler's status is reported as not ready.
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

            # Ensure we are processing the same goal state only once
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)

            # Force a new goal state incarnation, only then will we attempt the upgrade again
            test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<", "<Incarnation>3<")

            # Ensure disable won't fail by making launch_command a no-op
            with patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.launch_command') as patch_launch_command:
                exthandlers_handler.run()
                self.assertEqual(2, patch_get_disable_command.call_count)
                self.assertEqual(1, patch_get_enable_command.call_count)
                self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails_incorrect_zip(self, patch_get_disable_command,
                                                                                      *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        # The download logic has retry logic that sleeps before each try - make sleep a no-op.
        with patch("time.sleep"):
            with patch("zipfile.ZipFile.extractall") as patch_zipfile_extractall:
                with patch(
                        'azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
                    patch_zipfile_extractall.side_effect = raise_ioerror
                    # The zipfile was corrupt and the upgrade sequence failed
                    exthandlers_handler.run()

                    # We never called the disable of the old version due to the failure when unzipping the new version,
                    # nor the enable of the new version
                    self.assertEqual(0, patch_get_disable_command.call_count)
                    self.assertEqual(0, patch_get_enable_command.call_count)

                    # Ensure we are processing the same goal state only once
                    loop_run = 5
                    for x in range(loop_run):
                        exthandlers_handler.run()

                    self.assertEqual(0, patch_get_disable_command.call_count)
                    self.assertEqual(0, patch_get_enable_command.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__old_handler_reports_failure_on_disable_fail_on_update(self, patch_get_disable_command, *args):
        old_version, new_version = "1.0.0", "1.0.1"
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch.object(ExtHandlerInstance, "report_event", autospec=True) as patch_report_event:
            exthandlers_handler.run()  # Download the new update the first time, and then we patch the download method.
            self.assertEqual(1, patch_get_disable_command.call_count)

            old_version_args, old_version_kwargs = patch_report_event.call_args
            new_version_args, new_version_kwargs = patch_report_event.call_args_list[0]

            self.assertEqual(new_version_args[0].ext_handler.properties.version, new_version,
                             "The first call to report event should be from the new version of the ext-handler "
                             "to report download succeeded")

            self.assertEqual(new_version_kwargs['message'], "Download succeeded",
                             "The message should be Download Succedded")

            self.assertEqual(old_version_args[0].ext_handler.properties.version, old_version,
                             "The last report event call should be from the old version ext-handler "
                             "to report the event from the previous version")

            self.assertFalse(old_version_kwargs['is_success'], "The last call to report event should be for a failure")

            self.assertTrue('Error' in old_version_kwargs['message'], "No error reported")

            # This is ensuring that the error status is being written to the new version
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version=new_version)

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_update_command')
    def test_upgrade_failure_with_exception_handling(self, patch_get_update_command,
                                                     patch_handle_ext_handler_error, *args):
        """
        Extension upgrade failure should not be retried
        """
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_update_command,
                                                                                          *args)

        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)
        self.assertEqual(1, patch_handle_ext_handler_error.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_pass_when_continue_on_update_failure_is_true_and_prev_version_disable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "This should be called twice, for both disable and uninstall")

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_extension_upgrade_should_pass_when_continue_on_update_failue_is_true_and_prev_version_uninstall_fails(
            self, patch_get_uninstall_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_uninstall_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            self.assertEqual(1, patch_get_uninstall_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "This should be called twice, for both disable and uninstall")

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_false_and_prev_version_disable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=False) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(1, mock_continue_on_update_failure.call_count,
                             "The first call would raise an exception")

        # Assert test scenario
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_false_and_prev_version_uninstall_fails(
            self, patch_get_uninstall_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_uninstall_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=False) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            self.assertEqual(1, patch_get_uninstall_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "The second call would raise an exception")

        # Assert test scenario
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_true_and_old_disable_and_new_enable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command', return_value="exit 1")\
                    as patch_get_enable:

                # These are just testing the mocks have been called and asserting the test conditions have been met
                exthandlers_handler.run()
                self.assertEqual(1, patch_get_disable_command.call_count)
                self.assertEqual(2, mock_continue_on_update_failure.call_count)
                self.assertEqual(1, patch_get_enable.call_count)

        # Assert test scenario
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True)
    def test_uninstall_rc_env_var_should_report_not_run_for_non_update_calls_to_exthandler_run(
            self, patch_continue_on_update, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(Mock(), *args)

        with patch.object(CGroupConfigurator.get_instance(), "start_extension_command",
                          side_effect=[ExtensionError("Disable Failed"), "ok", ExtensionError("uninstall failed"),
                                       "ok", "ok", "New enable run ok"]) as patch_start_cmd:
            exthandlers_handler.run()
            _, update_kwargs = patch_start_cmd.call_args_list[1]
            _, install_kwargs = patch_start_cmd.call_args_list[3]
            _, enable_kwargs = patch_start_cmd.call_args_list[4]

            # Ensure that the env variables were present in the first run when failures were thrown for update
            self.assertEqual(2, patch_continue_on_update.call_count)
            self.assertTrue(
                '-update' in update_kwargs['command'] and ExtCommandEnvVariable.DisableReturnCode in update_kwargs['env'],
                "The update command call should have Disable Failed in env variable")
            self.assertTrue(
                '-install' in install_kwargs['command'] and ExtCommandEnvVariable.DisableReturnCode not in install_kwargs[
                    'env'],
                "The Disable Failed env variable should be removed from install command")
            self.assertTrue(
                '-install' in install_kwargs['command'] and ExtCommandEnvVariable.UninstallReturnCode in install_kwargs[
                    'env'],
                "The install command call should have Uninstall Failed in env variable")
            self.assertTrue(
                '-enable' in enable_kwargs['command'] and ExtCommandEnvVariable.UninstallReturnCode in enable_kwargs['env'],
                "The enable command call should have Uninstall Failed in env variable")

            # Initiating another run which shouldn't have any failed env variables in it if no failures
            # Updating Incarnation
            test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<", "<Incarnation>3<")
            exthandlers_handler.run()
            _, new_enable_kwargs = patch_start_cmd.call_args

            # Ensure the new run didn't have Disable Return Code env variable
            self.assertNotIn(ExtCommandEnvVariable.DisableReturnCode, new_enable_kwargs['env'])

            # Ensure the new run had Uninstall Return Code env variable == NOT_RUN
            self.assertIn(ExtCommandEnvVariable.UninstallReturnCode, new_enable_kwargs['env'])
            self.assertTrue(
                new_enable_kwargs['env'][ExtCommandEnvVariable.UninstallReturnCode] == NOT_RUN)

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    def test_ext_path_and_version_env_variables_set_for_ever_operation(self, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        with patch.object(CGroupConfigurator.get_instance(), "start_extension_command") as patch_start_cmd:
            exthandlers_handler.run()

            # Extension Path and Version should be set for all launch_command calls
            for args, kwargs in patch_start_cmd.call_args_list:
                self.assertIn(ExtCommandEnvVariable.ExtensionPath, kwargs['env'])
                self.assertIn('OSTCExtensions.ExampleHandlerLinux-1.0.0',
                              kwargs['env'][ExtCommandEnvVariable.ExtensionPath])
                self.assertIn(ExtCommandEnvVariable.ExtensionVersion, kwargs['env'])
                self.assertEqual("1.0.0", kwargs['env'][ExtCommandEnvVariable.ExtensionVersion])

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")

    @patch("azurelinuxagent.common.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_ext_sequence_no_should_be_set_for_every_command_call(self, _, *args):
        test_data = WireProtocolData(DATA_FILE_MULTIPLE_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        with patch("subprocess.Popen") as patch_popen:
            exthandlers_handler.run()

            for _, kwargs in patch_popen.call_args_list:
                self.assertIn(ExtCommandEnvVariable.ExtensionSeqNumber, kwargs['env'])
                self.assertEqual(kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber], "0")

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")

        # Next incarnation and seq for extensions, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.ext_conf = test_data.ext_conf.replace('seqNo="0"', 'seqNo="1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        with patch("subprocess.Popen") as patch_popen:
            exthandlers_handler.run()

            for _, kwargs in patch_popen.call_args_list:
                self.assertIn(ExtCommandEnvVariable.ExtensionSeqNumber, kwargs['env'])
                self.assertEqual(kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber], "1")

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")

    def test_ext_sequence_no_should_be_set_from_within_extension(self, *args):

        test_file_name = "testfile.sh"
        handler_json = {
            "installCommand": test_file_name,
            "uninstallCommand": test_file_name,
            "updateCommand": test_file_name,
            "enableCommand": test_file_name,
            "disableCommand": test_file_name,
            "rebootAfterInstall": False,
            "reportHeartbeat": False,
            "continueOnUpdateFailure": False
        }
        manifest = HandlerManifest({'handlerManifest': handler_json})

        # Script prints env variables passed to this process and prints all starting with ConfigSequenceNumber
        test_file = """
                printenv | grep ConfigSequenceNumber
                """

        base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.0', test_file_name)
        self.create_script(test_file_name, test_file, base_dir)

        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        expected_seq_no = 0

        with patch.object(ExtHandlerInstance, "load_manifest", return_value=manifest):
            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()

                for _, kwargs in mock_report_event.call_args_list:
                    # The output is of the format - 'testfile.sh\n[stdout]ConfigSequenceNumber=N\n[stderr]'
                    if test_file_name not in kwargs['message']:
                        continue
                    self.assertIn("{0}={1}".format(ExtCommandEnvVariable.ExtensionSeqNumber, expected_seq_no),
                                  kwargs['message'])

            # Update goal state, extension version and seq no
            test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
            test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
            test_data.ext_conf = test_data.ext_conf.replace('seqNo="0"', 'seqNo="1"')
            test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')
            expected_seq_no = 1
            base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.1', test_file_name)
            self.create_script(test_file_name, test_file, base_dir)

            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()

                for _, kwargs in mock_report_event.call_args_list:
                    # The output is of the format - 'testfile.sh\n[stdout]ConfigSequenceNumber=N\n[stderr]'
                    if test_file_name not in kwargs['message']:
                        continue
                    self.assertIn("{0}={1}".format(ExtCommandEnvVariable.ExtensionSeqNumber, expected_seq_no),
                                  kwargs['message'])

    def test_correct_exit_code_should_be_set_on_uninstall_cmd_failure(self, *args):
        test_file_name = "testfile.sh"
        test_error_file_name = "error.sh"
        handler_json = {
            "installCommand": test_file_name + " -install",
            "uninstallCommand": test_error_file_name,
            "updateCommand": test_file_name + " -update",
            "enableCommand": test_file_name + " -enable",
            "disableCommand": test_error_file_name,
            "rebootAfterInstall": False,
            "reportHeartbeat": False,
            "continueOnUpdateFailure": True
        }
        manifest = HandlerManifest({'handlerManifest': handler_json})

        # Script prints env variables passed to this process and prints all starting with ConfigSequenceNumber
        test_file = """
            printenv | grep AZURE_
        """

        exit_code = 151
        test_error_content = """
            exit %s
        """ % exit_code

        error_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.0', test_error_file_name)
        self.create_script(test_error_file_name, test_error_content, error_dir)

        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(Mock(), *args)

        base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.1', test_file_name)
        self.create_script(test_file_name, test_file, base_dir)

        with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.load_manifest", return_value=manifest):
            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()

                _, disable_kwargs = mock_report_event.call_args_list[1]
                _, update_kwargs = mock_report_event.call_args_list[2]
                _, uninstall_kwargs = mock_report_event.call_args_list[3]
                _, install_kwargs = mock_report_event.call_args_list[4]
                _, enable_kwargs = mock_report_event.call_args_list[5]

                self.assertIn("%s=%s" % (ExtCommandEnvVariable.DisableReturnCode, exit_code), update_kwargs['message'])
                self.assertIn("%s=%s" % (ExtCommandEnvVariable.UninstallReturnCode, exit_code), install_kwargs['message'])
                self.assertIn("%s=%s" % (ExtCommandEnvVariable.UninstallReturnCode, exit_code), enable_kwargs['message'])


@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionSequencing(AgentTestCase):

    def _create_mock(self, mock_http_get, MockCryptUtil):
        test_data = WireProtocolData(DATA_FILE)

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()
        protocol.get_artifacts_profile = MagicMock()

        handler = get_exthandlers_handler()
        handler.protocol_util.get_protocol = Mock(return_value=protocol)
        handler.ext_handlers, handler.last_etag = protocol.get_ext_handlers()
        conf.get_enable_overprovisioning = Mock(return_value=False)

        def wait_for_handler_successful_completion(prev_handler, wait_until):
            return orig_wait_for_handler_successful_completion(prev_handler,
                                                               datetime.datetime.utcnow() + datetime.timedelta(
                                                                   seconds=5))

        orig_wait_for_handler_successful_completion = handler.wait_for_handler_successful_completion
        handler.wait_for_handler_successful_completion = wait_for_handler_successful_completion
        return handler

    def _set_dependency_levels(self, dependency_levels, exthandlers_handler):
        '''
        Creates extensions with the given dependencyLevel
        '''
        handler_map = dict()
        all_handlers = []
        for h, level in dependency_levels:
            if handler_map.get(h) is None:
                handler = ExtHandler(name=h)
                extension = Extension(name=h)
                handler.properties.state = "enabled"
                handler.properties.extensions.append(extension)
                handler_map[h] = handler
                all_handlers.append(handler)

            handler = handler_map[h]
            for ext in handler.properties.extensions:
                ext.dependencyLevel = level

        exthandlers_handler.ext_handlers.extHandlers = []
        for handler in all_handlers:
            exthandlers_handler.ext_handlers.extHandlers.append(handler)

    def _validate_extension_sequence(self, expected_sequence, exthandlers_handler):
        installed_extensions = [a[0].name for a, k in exthandlers_handler.handle_ext_handler.call_args_list]
        self.assertListEqual(expected_sequence, installed_extensions,
                             "Expected and actual list of extensions are not equal")

    def _run_test(self, extensions_to_be_failed, expected_sequence, exthandlers_handler):
        '''
        Mocks get_ext_handling_status() to mimic error status for a given extension.
        Calls ExtHandlersHandler.run()
        Verifies if the ExtHandlersHandler.handle_ext_handler() was called with appropriate extensions
        in the expected order.
        '''

        def get_ext_handling_status(ext):
            status = "error" if ext.name in extensions_to_be_failed else "success"
            return status

        ExtHandlerInstance.get_ext_handling_status = MagicMock(side_effect=get_ext_handling_status)
        exthandlers_handler.handle_ext_handler = MagicMock()
        exthandlers_handler.run()
        self._validate_extension_sequence(expected_sequence, exthandlers_handler)

    def test_handle_ext_handlers(self, *args):
        '''
        Tests extension sequencing among multiple extensions with dependencies.
        This test introduces failure in all possible levels and extensions.
        Verifies that the sequencing is in the expected order and a failure in one extension
        skips the rest of the extensions in the sequence.
        '''
        exthandlers_handler = self._create_mock(*args)

        self._set_dependency_levels([("A", 3), ("B", 2), ("C", 2), ("D", 1), ("E", 1), ("F", 1), ("G", 1)],
                                    exthandlers_handler)

        extensions_to_be_failed = []
        expected_sequence = ["D", "E", "F", "G", "B", "C", "A"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["D"]
        expected_sequence = ["D"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["E"]
        expected_sequence = ["D", "E"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["F"]
        expected_sequence = ["D", "E", "F"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["G"]
        expected_sequence = ["D", "E", "F", "G"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["B"]
        expected_sequence = ["D", "E", "F", "G", "B"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["C"]
        expected_sequence = ["D", "E", "F", "G", "B", "C"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["A"]
        expected_sequence = ["D", "E", "F", "G", "B", "C", "A"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

    def test_handle_ext_handlers_with_uninstallation(self, *args):
        '''
        Tests extension sequencing among multiple extensions with dependencies when
        some extension are to be uninstalled.
        Verifies that the sequencing is in the expected order and the uninstallation takes place
        prior to all the installation/enable.
        '''
        exthandlers_handler = self._create_mock(*args)

        # "A", "D" and "F" are marked as to be uninstalled
        self._set_dependency_levels([("A", 0), ("B", 2), ("C", 2), ("D", 0), ("E", 1), ("F", 0), ("G", 1)],
                                    exthandlers_handler)

        extensions_to_be_failed = []
        expected_sequence = ["A", "D", "F", "E", "G", "B", "C"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

    def test_handle_ext_handlers_fallback(self, *args):
        '''
        This test makes sure that the extension sequencing is applied only when the user specifies
        dependency information in the extension.
        When there is no dependency specified, the agent is expected to assign dependencyLevel=0 to all extension.
        Also, it is expected to install all the extension no matter if there is any failure in any of the extensions.
        '''
        exthandlers_handler = self._create_mock(*args)

        self._set_dependency_levels([("A", 1), ("B", 1), ("C", 1), ("D", 1), ("E", 1), ("F", 1), ("G", 1)],
                                    exthandlers_handler)

        # Expected sequence must contain all the extensions in the given order.
        # The following test cases verfy against this same expected sequence no matter if any extension failed
        expected_sequence = ["A", "B", "C", "D", "E", "F", "G"]

        # Make sure that failure in any extension does not prevent other extensions to be installed
        extensions_to_be_failed = []
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["A"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["B"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["C"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["D"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["E"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["F"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

        extensions_to_be_failed = ["G"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)


class TestInVMArtifactsProfile(AgentTestCase):
    def test_it_should_parse_boolean_values(self):
        profile_json = '{ "onHold": true }'
        profile = InVMArtifactsProfile(profile_json)
        self.assertTrue(profile.is_on_hold(), "Failed to parse '{0}'".format(profile_json))

        profile_json = '{ "onHold": false }'
        profile = InVMArtifactsProfile(profile_json)
        self.assertFalse(profile.is_on_hold(), "Failed to parse '{0}'".format(profile_json))

    def test_it_should_parse_boolean_values_encoded_as_strings(self):
        profile_json = '{ "onHold": "true" }'
        profile = InVMArtifactsProfile(profile_json)
        self.assertTrue(profile.is_on_hold(), "Failed to parse '{0}'".format(profile_json))

        profile_json = '{ "onHold": "false" }'
        profile = InVMArtifactsProfile(profile_json)
        self.assertFalse(profile.is_on_hold(), "Failed to parse '{0}'".format(profile_json))

        profile_json = '{ "onHold": "TRUE" }'
        profile = InVMArtifactsProfile(profile_json)
        self.assertTrue(profile.is_on_hold(), "Failed to parse '{0}'".format(profile_json))


@skip_if_predicate_false(are_cgroups_enabled, "Does not run when Cgroups are not enabled")
@patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
@patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=True)
@patch("azurelinuxagent.common.conf.get_cgroups_enforce_limits", return_value=False)
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionWithCGroupsEnabled(AgentTestCase):
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

    def _assert_ext_status(self, report_ext_status, expected_status,
                           expected_seq_no):
        self.assertTrue(report_ext_status.called)
        args, kw = report_ext_status.call_args
        ext_status = args[-1]
        self.assertEquals(expected_status, ext_status.status)
        self.assertEquals(expected_seq_no, ext_status.sequenceNumber)

    def _create_mock(self, test_data, mock_http_get, mock_crypt_util, *args):
        """Test enable/disable/uninstall of an extension"""
        ext_handler = get_exthandlers_handler()
        monitor_handler = get_monitor_handler()

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        mock_crypt_util.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        ext_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        monitor_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        return ext_handler, monitor_handler, protocol

    @attr('requires_sudo')
    def test_ext_handler_with_cgroup_enabled(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, _, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.1")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"",
                                                        "seqNo=\"2\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.1", "1.2.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"2\"",
                                                        "seqNo=\"3\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.2.0")

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @attr('requires_sudo')
    def test_ext_handler_and_monitor_handler_with_cgroup_enabled(self, patch_add_event, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, monitor_handler, protocol = self._create_mock(test_data, *args)

        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()

        self.assertEqual(patch_add_event.call_count, 4)

        name = patch_add_event.call_args[0][0]
        fields = patch_add_event.call_args[1]

        self.assertEqual(name, "WALinuxAgent")
        self.assertEqual(fields["op"], "ExtensionMetricsData")
        self.assertEqual(fields["is_success"], True)
        self.assertEqual(fields["log_event"], False)
        self.assertEqual(fields["is_internal"], False)
        self.assertIsInstance(fields["message"], ustr)

        monitor_handler.stop()

    @attr('requires_sudo')
    def test_ext_handler_with_systemd_cgroup_enabled(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        from azurelinuxagent.common.cgroupapi import CGroupsApi
        print(CGroupsApi._is_systemd())

        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, _, protocol = self._create_mock(test_data, *args)

        # Test enable scenario.
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"0\"",
                                                        "seqNo=\"1\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>2<",
                                                            "<Incarnation>3<")
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.1")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"1\"",
                                                        "seqNo=\"2\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>3<",
                                                            "<Incarnation>4<")
        test_data.ext_conf = test_data.ext_conf.replace("1.1.1", "1.2.0")
        test_data.ext_conf = test_data.ext_conf.replace("seqNo=\"2\"",
                                                        "seqNo=\"3\"")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>4<",
                                                            "<Incarnation>5<")
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "NotReady",
                                    1, "1.2.0")

        # Test uninstall
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>5<",
                                                            "<Incarnation>6<")
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>6<",
                                                            "<Incarnation>7<")
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)


class TestExtensionUpdateOnFailure(ExtensionTestCase):

    @staticmethod
    def _get_ext_handler_instance(name, version, handler=None, continue_on_update_failure=False):

        handler_json = {
            "installCommand": "sample.py -install",
            "uninstallCommand": "sample.py -uninstall",
            "updateCommand": "sample.py -update",
            "enableCommand": "sample.py -enable",
            "disableCommand": "sample.py -disable",
            "rebootAfterInstall": False,
            "reportHeartbeat": False,
            "continueOnUpdateFailure": continue_on_update_failure
        }

        if handler:
            handler_json.update(handler)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = version
        ext_handler = ExtHandler(name=name)
        ext_handler.properties = ext_handler_properties
        ext_handler_i = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)
        ext_handler_i.load_manifest = MagicMock(return_value=HandlerManifest({'handlerManifest': handler_json}))
        fileutil.mkdir(ext_handler_i.get_base_dir())
        return ext_handler_i

    def test_disable_failed_env_variable_should_be_set_for_update_cmd_when_continue_on_update_failure_is_true(
            self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=True)

        with patch.object(CGroupConfigurator.get_instance(), "start_extension_command",
                          side_effect=ExtensionError('disable Failed')) as patch_start_cmd:
            with self.assertRaises(ExtensionError):
                ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

            args, kwargs = patch_start_cmd.call_args

            self.assertTrue('-update' in kwargs['command'] and ExtCommandEnvVariable.DisableReturnCode in kwargs['env'],
                            "The update command should have Disable Failed in env variable")

    def test_uninstall_failed_env_variable_should_set_for_install_when_continue_on_update_failure_is_true(
            self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=True)

        with patch.object(CGroupConfigurator.get_instance(), "start_extension_command",
                          side_effect=['ok', 'ok', ExtensionError('uninstall Failed'), 'ok']) as patch_start_cmd:

            ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

            args, kwargs = patch_start_cmd.call_args

            self.assertTrue('-install' in kwargs['command'] and ExtCommandEnvVariable.UninstallReturnCode in kwargs['env'],
                            "The install command should have Uninstall Failed in env variable")

    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_disable_failure(self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=False)

        with patch.object(ExtHandlerInstance, "disable", side_effect=ExtensionError("Disable Failed")):
            with self.assertRaises(ExtensionUpdateError) as error:
                # Ensure the error is of type ExtensionUpdateError
                ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

            msg = str(error.exception)
            self.assertIn("Disable Failed", msg, "Update should fail with Disable Failed error")
            self.assertIn("ExtensionError", msg, "The Exception should initially be propagated as ExtensionError")

    @patch("azurelinuxagent.common.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_uninstall_failure(self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=False)

        with patch.object(ExtHandlerInstance, "uninstall", side_effect=ExtensionError("Uninstall Failed")):
            with self.assertRaises(ExtensionUpdateError) as error:
                # Ensure the error is of type ExtensionUpdateError
                ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

            msg = str(error.exception)
            self.assertIn("Uninstall Failed", msg, "Update should fail with Uninstall Failed error")
            self.assertIn("ExtensionError", msg, "The Exception should initially be propagated as ExtensionError")

    @patch("azurelinuxagent.common.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_true_on_command_failure(self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=True)

        # Disable Failed and update failed
        with patch.object(ExtHandlerInstance, "disable", side_effect=ExtensionError("Disable Failed")):
            with patch.object(ExtHandlerInstance, "update", side_effect=ExtensionError("Update Failed")):
                with self.assertRaises(ExtensionError) as error:
                    ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)
                msg = str(error.exception)
                self.assertIn("Update Failed", msg, "Update should fail with Update Failed error")
                self.assertNotIn("ExtensionUpdateError", msg, "The exception should not be ExtensionUpdateError")

        # Uninstall Failed and install failed
        with patch.object(ExtHandlerInstance, "uninstall", side_effect=ExtensionError("Uninstall Failed")):
            with patch.object(ExtHandlerInstance, "install", side_effect=ExtensionError("Install Failed")):
                with self.assertRaises(ExtensionError) as error:
                    ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)
                msg = str(error.exception)
                self.assertIn("Install Failed", msg, "Update should fail with Install Failed error")
                self.assertNotIn("ExtensionUpdateError", msg, "The exception should not be ExtensionUpdateError")

    @patch("azurelinuxagent.common.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_env_variable_should_not_set_when_continue_on_update_failure_is_false(self, *args):
        old_handler_i = self._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = self._get_ext_handler_instance('foo', '1.0.1', continue_on_update_failure=False)

        # When Disable Fails
        with patch.object(ExtHandlerInstance, "launch_command") as patch_launch_command:
            with patch.object(ExtHandlerInstance, "disable", side_effect=ExtensionError("Disable Failed")):
                with self.assertRaises(ExtensionUpdateError):
                    ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

                self.assertEqual(0, patch_launch_command.call_count, "Launch command shouldn't be called even once for"
                                                                     " disable failures")

        # When Uninstall Fails
        with patch.object(ExtHandlerInstance, "launch_command") as patch_launch_command:
            with patch.object(ExtHandlerInstance, "uninstall", side_effect=ExtensionError("Uninstall Failed")):
                with self.assertRaises(ExtensionUpdateError):
                    ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

                self.assertEqual(2, patch_launch_command.call_count, "Launch command should be called 2 times for "
                                                                     "Disable->Update")

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
    def test_failed_env_variables_should_be_set_from_within_extension_commands(self, *args):
        """
        This test will test from the perspective of the extensions command weather the env variables are
        being set for those processes
        """

        test_file_name = "testfile.sh"
        update_file_name = test_file_name + " -update"
        install_file_name = test_file_name + " -install"
        old_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance('foo', '1.0.0')
        new_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance(
            'foo', '1.0.1',
            handler={"updateCommand": update_file_name, "installCommand": install_file_name},
            continue_on_update_failure=True
        )

        # Script prints env variables passed to this process and prints all starting with AZURE_
        test_file = """
            printenv | grep AZURE_
            """

        self.create_script(file_name=test_file_name, contents=test_file,
                           file_path=os.path.join(new_handler_i.get_base_dir(), test_file_name))

        with patch.object(new_handler_i, 'report_event', autospec=True) as mock_report:
            # Since we're not mocking the azurelinuxagent.common.cgroupconfigurator..handle_process_completion,
            # both disable.cmd and uninstall.cmd would raise ExtensionError exceptions and set the
            # ExtCommandEnvVariable.DisableReturnCode and ExtCommandEnvVariable.UninstallReturnCode env variables.
            # For update and install we're running the script above to print all the env variables starting with AZURE_
            # and verify accordingly if the corresponding env variables are set properly or not
            ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)

            _, update_kwargs = mock_report.call_args_list[0]
            _, install_kwargs = mock_report.call_args_list[1]

            # Ensure we're checking variables for update scenario
            self.assertIn(update_file_name, update_kwargs['message'])
            self.assertIn(ExtCommandEnvVariable.DisableReturnCode, update_kwargs['message'])
            self.assertTrue(ExtCommandEnvVariable.ExtensionPath in update_kwargs['message'] and
                            ExtCommandEnvVariable.ExtensionVersion in update_kwargs['message'])
            self.assertNotIn(ExtCommandEnvVariable.UninstallReturnCode, update_kwargs['message'])

            # Ensure we're checking variables for install scenario
            self.assertIn(install_file_name, install_kwargs['message'])
            self.assertIn(ExtCommandEnvVariable.UninstallReturnCode, install_kwargs['message'])
            self.assertTrue(ExtCommandEnvVariable.ExtensionPath in install_kwargs['message'] and
                            ExtCommandEnvVariable.ExtensionVersion in install_kwargs['message'])
            self.assertNotIn(ExtCommandEnvVariable.DisableReturnCode, install_kwargs['message'])

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
    def test_correct_exit_code_should_set_on_disable_cmd_failure(self, _):
        test_env_file_name = "test_env.sh"
        test_failure_file_name = "test_fail.sh"
        # update_file_name = test_env_file_name + " -update"
        old_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance('foo', '1.0.0', handler={
            "disableCommand": test_failure_file_name,
            "uninstallCommand": test_failure_file_name})
        new_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance(
            'foo', '1.0.1',
            handler={"updateCommand": test_env_file_name,
                     "updateMode": "UpdateWithoutInstall"},
            continue_on_update_failure=True
        )

        exit_code = 150
        error_test_file = """
                    exit %s
                    """ % exit_code

        test_env_file = """
            printenv | grep AZURE_
            """

        self.create_script(file_name=test_env_file_name, contents=test_env_file,
                           file_path=os.path.join(new_handler_i.get_base_dir(), test_env_file_name))
        self.create_script(file_name=test_failure_file_name, contents=error_test_file,
                           file_path=os.path.join(old_handler_i.get_base_dir(), test_failure_file_name))

        with patch.object(new_handler_i, 'report_event', autospec=True) as mock_report:

            uninstall_rc = ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i, new_handler_i)
            _, kwargs = mock_report.call_args

            self.assertEqual(exit_code, uninstall_rc)
            self.assertIn("%s=%s" % (ExtCommandEnvVariable.DisableReturnCode, exit_code), kwargs['message'])

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.0001))
    def test_timeout_code_should_set_on_cmd_timeout(self, _):
        test_env_file_name = "test_env.sh"
        test_failure_file_name = "test_fail.sh"
        old_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance('foo', '1.0.0', handler={
            "disableCommand": test_failure_file_name,
            "uninstallCommand": test_failure_file_name})
        new_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance(
            'foo', '1.0.1',
            handler={"updateCommand": test_env_file_name + " -u", "installCommand": test_env_file_name + " -i"},
            continue_on_update_failure=True
        )

        exit_code = 156
        error_test_file = """
            sleep 1m
            exit %s
        """ % exit_code

        test_env_file = """
            printenv | grep AZURE_
        """

        self.create_script(file_name=test_env_file_name, contents=test_env_file,
                           file_path=os.path.join(new_handler_i.get_base_dir(), test_env_file_name))
        self.create_script(file_name=test_failure_file_name, contents=error_test_file,
                           file_path=os.path.join(old_handler_i.get_base_dir(), test_failure_file_name))

        with patch.object(new_handler_i, 'report_event', autospec=True) as mock_report:
            uninstall_rc = ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i,
                                                                                             new_handler_i)
            _, update_kwargs = mock_report.call_args_list[0]
            _, install_kwargs = mock_report.call_args_list[1]

            self.assertNotEqual(exit_code, uninstall_rc)
            self.assertEqual(ExtensionErrorCodes.PluginHandlerScriptTimedout, uninstall_rc)
            self.assertTrue(test_env_file_name + " -i" in install_kwargs['message'] and "%s=%s" % (
                ExtCommandEnvVariable.UninstallReturnCode, ExtensionErrorCodes.PluginHandlerScriptTimedout) in
                            install_kwargs['message'])
            self.assertTrue(test_env_file_name + " -u" in update_kwargs['message'] and "%s=%s" % (
                ExtCommandEnvVariable.DisableReturnCode, ExtensionErrorCodes.PluginHandlerScriptTimedout) in
                            update_kwargs['message'])

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.0001))
    def test_success_code_should_set_in_env_variables_on_cmd_success(self, _):
        test_env_file_name = "test_env.sh"
        test_success_file_name = "test_success.sh"
        old_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance('foo', '1.0.0', handler={
            "disableCommand": test_success_file_name,
            "uninstallCommand": test_success_file_name})
        new_handler_i = TestExtensionUpdateOnFailure._get_ext_handler_instance(
            'foo', '1.0.1',
            handler={"updateCommand": test_env_file_name + " -u", "installCommand": test_env_file_name + " -i"},
            continue_on_update_failure=False
        )

        exit_code = 0
        success_test_file = """
                exit %s
            """ % exit_code

        test_env_file = """
                printenv | grep AZURE_
            """

        self.create_script(file_name=test_env_file_name, contents=test_env_file,
                           file_path=os.path.join(new_handler_i.get_base_dir(), test_env_file_name))
        self.create_script(file_name=test_success_file_name, contents=success_test_file,
                           file_path=os.path.join(old_handler_i.get_base_dir(), test_success_file_name))

        with patch.object(new_handler_i, 'report_event', autospec=True) as mock_report:
            uninstall_rc = ExtHandlersHandler._update_extension_handler_and_return_if_failed(old_handler_i,
                                                                                             new_handler_i)
            _, update_kwargs = mock_report.call_args_list[0]
            _, install_kwargs = mock_report.call_args_list[1]

            self.assertEqual(exit_code, uninstall_rc)
            self.assertTrue(test_env_file_name + " -i" in install_kwargs['message'] and "%s=%s" % (
                ExtCommandEnvVariable.UninstallReturnCode, exit_code) in install_kwargs['message'])
            self.assertTrue(test_env_file_name + " -u" in update_kwargs['message'] and "%s=%s" % (
                ExtCommandEnvVariable.DisableReturnCode, exit_code) in update_kwargs['message'])


if __name__ == '__main__':
    unittest.main()
