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

from nose.tools import assert_equal

from tests.protocol.mockwiredata import *

from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.ga.exthandlers import *
from azurelinuxagent.common.protocol.wire import WireProtocol, InVMArtifactsProfile


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
        CGroups.disable()

    @classmethod
    def tearDownClass(cls):
        CGroups.enable()


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

    def _assert_no_handler_status(self, report_vm_status):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args
        vm_status = args[0]
        self.assertEquals(0, len(vm_status.vmAgent.extensionHandlers))
        return

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil):
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

    @skip_if_predicate_true(do_not_run_test, "Incorrect test - Change in behavior in reporting events now.")
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_download_failure_transient(self, mock_add_event, *args):
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

    @skip_if_predicate_true(do_not_run_test, "Incorrect test - Change in behavior in reporting events now.")
    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.common.event.add_event')
    def test_ext_handler_download_failure_permanent(self, mock_add_event, mock_error_state, *args):
        test_data = WireProtocolData(DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.get_ext_handler_pkgs = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True
        exthandlers_handler.run()
        self.assertEquals(1, mock_add_event.call_count)
        args, kw = mock_add_event.call_args_list[0]
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("Failed to get ext handler pkgs" in kw['message'])
        self.assertTrue("Failed to get artifact" in kw['message'])
        self.assertEquals("GetArtifactExtended", kw['op'])

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
            self.assertEqual(1, patch_handle_ext_handler.call_count)

        # enable extension handling blocking
        conf.get_enable_overprovisioning = Mock(return_value=True)
        with patch.object(ExtHandlersHandler, 'handle_ext_handler') as patch_handle_ext_handler:
            exthandlers_handler.handle_ext_handlers()
            self.assertEqual(0, patch_handle_ext_handler.call_count)

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
        wait_until = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
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

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.install', side_effect=ExtHandlerInstance.install, autospec=True)
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

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_install_command')
    def test_install_failure_check_exception_handling(self, patch_get_install_command, patch_handle_handle_ext_handler_error, *args):
        """
        When extension install fails, the operation should be reported to our telemetry service.
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure install is unsuccessful
        patch_get_install_command.return_value = "exit.sh 1"
        exthandlers_handler.run()

        self.assertEqual(1, protocol.report_vm_status.call_count)
        self.assertEqual(1, patch_handle_handle_ext_handler_error.call_count)

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

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command')
    def test_enable_failure_check_exception_handling(self, patch_get_enable_command,
                                                     patch_handle_handle_ext_handler_error, *args):
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
        self.assertEqual(1, patch_handle_handle_ext_handler_error.call_count)

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

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_disable_failure_with_exception_handling(self, patch_get_disable_command,
                                                     patch_handle_handle_ext_handler_error, *args):
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
        self.assertEqual(1, patch_handle_handle_ext_handler_error.call_count)

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
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()
        self.assertEqual(0, patch_get_update_command.call_count)

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<",
                                                            "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"',
                                                        'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0',
                                                        '1.0.1')

        # Update command should fail
        patch_get_update_command.return_value = "exit 1"
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)

        # On the next iteration, update should not be retried
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)

        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails(self, patch_get_disable_command, *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Disable of the old extn fails
        patch_get_disable_command.return_value = "exit 1"
        exthandlers_handler.run()  # Download the new update the first time, and then we patch the download method.

        with patch('azurelinuxagent.common.protocol.restapi.Protocol.download_ext_handler_pkg') as patch_download:
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            self.assertEqual(loop_run + 1, patch_get_disable_command.call_count)  # counting the earlier run done to
            # download the new update
            self.assertEqual(0, patch_download.call_count)  # The download should never be called.

        # On the next iteration, update should not be retried
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails_and_recovers(self, patch_get_disable_command,
                                                                                     *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Disable of the old extn fails
        patch_get_disable_command.return_value = "exit 1"
        exthandlers_handler.run()  # Download the new update the first time, and then we patch the download method.
        self.assertEqual(1, patch_get_disable_command.call_count)

        with patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.launch_command') as patch_launch_command:
            exthandlers_handler.run()

        self.assertEqual(2, patch_get_disable_command.call_count)  # counting the earlier run done.

        with patch('azurelinuxagent.common.protocol.restapi.Protocol.download_ext_handler_pkg') as patch_download:
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            self.assertEqual(0, patch_download.call_count)  # The download should never be called.

        self.assertEqual(2, patch_get_disable_command.call_count)  # Disable is not called again after it recovered

        # The update recovered, and thus should be "Ready" now.
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test__extension_upgrade_failure_when_prev_version_disable_fails_incorrect_zip(self, patch_get_disable_command,
                                                                                      *args):
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()
        self.assertEqual(0, patch_get_disable_command.call_count)

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Disable of the old extn fails
        patch_get_disable_command.return_value = "exit 1"
        with patch("zipfile.ZipFile.extractall") as patch_zipfile_extractall:
            patch_zipfile_extractall.side_effect = raise_ioerror
            exthandlers_handler.run()  # Check if the zipfile was corrupt and re-download again in the next run.

        # Disable of the old extn fails
        patch_get_disable_command.return_value = "exit 1"
        exthandlers_handler.run()  # Download the new update the correctly, and then we patch the download method.

        with patch('azurelinuxagent.common.protocol.restapi.Protocol.download_ext_handler_pkg') as patch_download:
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            # failed to download earlier, thus doesn't need to add +1, like in the earlier test case
            self.assertEqual(loop_run + 1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_download.call_count)  # The download should never be called.

        # On the next iteration, update should not be retried
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlersHandler.handle_handle_ext_handler_error')
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_update_command')
    def test_upgrade_failure_with_exception_handling(self, patch_get_update_command,
                                                     patch_handle_handle_ext_handler_error, *args):
        """
        Extension upgrade failure should not be retried
        """
        test_data = WireProtocolData(DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()
        self.assertEqual(0, patch_get_update_command.call_count)

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')

        # Update command should fail
        patch_get_update_command.return_value = "exit 1"
        exthandlers_handler.run()
        self.assertEqual(1, patch_get_update_command.call_count)
        self.assertEqual(1, patch_handle_handle_ext_handler_error.call_count)


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



if __name__ == '__main__':
    unittest.main()
