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
import contextlib
import glob
import json
import os.path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
import zipfile

import datetime

from azurelinuxagent.common import conf
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.datacontract import get_properties
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.fileutil import read_file
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO, AGENT_NAME, \
    GOAL_STATE_AGENT_VERSION, CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION
from azurelinuxagent.ga.exthandlers import ExtHandlerState, ExtHandlersHandler, ExtHandlerInstance, HANDLER_PKG_EXT, \
    migrate_handler_state, get_exthandlers_handler, AGENT_STATUS_FILE, ExtCommandEnvVariable, \
    HandlerManifest, NOT_RUN, ValidHandlerStatus, HANDLER_NAME_PATTERN

from azurelinuxagent.ga.monitor import get_monitor_handler
from nose.plugins.attrib import attr
from tests.protocol import mockwiredata
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import are_cgroups_enabled, AgentTestCase, data_dir, i_am_root, MagicMock, Mock, \
    skip_if_predicate_false, patch
from tests.ga.extension_actor import get_extension_actor, get_protocol_and_handler, update_extension_actors, Actions

from azurelinuxagent.common.exception import ResourceGoneError, ExtensionDownloadError, ProtocolError, \
    ExtensionErrorCodes, ExtensionError, ExtensionUpdateError
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerProperties, ExtHandler, ExtHandlerStatus, \
    ExtensionStatus
from azurelinuxagent.common.protocol.wire import WireProtocol, InVMArtifactsProfile
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP

# Mocking the original sleep to reduce test execution time
SLEEP = time.sleep


SUCCESS_CODE_FROM_STATUS_FILE = 1


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
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.01))
        self.mock_sleep.start()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

    @staticmethod
    def _count_packages():
        return len(glob.glob(os.path.join(conf.get_lib_dir(), "*.zip")))

    @staticmethod
    def _count_extension_directories():
        paths = [os.path.join(conf.get_lib_dir(), p) for p in os.listdir(conf.get_lib_dir())]
        return len([p for p in paths
                    if os.path.isdir(p) and TestExtensionCleanup._is_extension_dir(p)])

    @staticmethod
    def _is_extension_dir(path):
        return re.match(HANDLER_NAME_PATTERN, os.path.basename(path)) is not None

    def _assert_ext_handler_status(self, aggregate_status, expected_status, version, expected_ext_handler_count=0):
        self.assertIsNotNone(aggregate_status, "Aggregate status should not be None")
        handler_statuses = aggregate_status['aggregateStatus']['handlerAggregateStatus']
        self.assertEqual(expected_ext_handler_count, len(handler_statuses),
                         "All ExtensionHandlers: {0}".format(handler_statuses))
        for ext_handler_status in handler_statuses:
            debug_info = "ExtensionHandler: {0}".format(ext_handler_status)
            self.assertEquals(expected_status, ext_handler_status['status'], debug_info)
            self.assertEquals(version, ext_handler_status['handlerVersion'], debug_info)
        return

    @contextlib.contextmanager
    def _setup_test_env(self, test_data):
        with mock_wire_protocol(test_data) as protocol:

            def mock_http_put(url, *args, **kwargs):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return None
                protocol.aggregate_status = json.loads(args[0])

            protocol.aggregate_status = None
            protocol.set_http_handlers(http_put_handler=mock_http_put)
            no_of_extensions = protocol.mock_wire_data.get_no_of_plugins_in_extension_config()
            exthandlers_handler = get_exthandlers_handler(protocol)
            yield exthandlers_handler, protocol, no_of_extensions

    def test_cleanup_leaves_installed_extensions(self):
        with self._setup_test_env(mockwiredata.DATA_FILE_MULTIPLE_EXT) as (exthandlers_handler, protocol, no_of_exts):
            exthandlers_handler.run()
            self.assertEqual(no_of_exts, TestExtensionCleanup._count_packages(),
                             "No of extensions in config doesn't match the packages")
            self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "No of extension directories doesnt match the no of extensions in GS")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=no_of_exts,
                                            version="1.0.0")

    def test_cleanup_removes_uninstalled_extensions(self):
        with self._setup_test_env(mockwiredata.DATA_FILE_MULTIPLE_EXT) as (exthandlers_handler, protocol, no_of_exts):
            exthandlers_handler.run()
            self.assertEqual(no_of_exts, TestExtensionCleanup._count_packages(),
                             "No of extensions in config doesn't match the packages")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=no_of_exts,
                                            version="1.0.0")

            # Update incarnation and extension config
            protocol.mock_wire_data.set_incarnation(2)
            protocol.mock_wire_data.set_extensions_config_state("uninstall")

            protocol.client.update_goal_state()
            exthandlers_handler.run()

            self.assertEqual(0, TestExtensionCleanup._count_packages(), "All packages must be deleted")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=0,
                                            version="1.0.0")
            self.assertEqual(0, TestExtensionCleanup._count_extension_directories(), "All extension directories should be removed")

    def test_cleanup_removes_orphaned_packages(self):
        no_of_orphaned_packages = 5
        with self._setup_test_env(mockwiredata.DATA_FILE_NO_EXT) as (exthandlers_handler, protocol, no_of_exts):
            self.assertEqual(no_of_exts, 0, "Test setup error - Extensions found in ExtConfig")

            # Create random extension directories
            for i in range(no_of_orphaned_packages):
                eh = ExtHandler(name='Random.Extension.ShouldNot.Be.There')
                eh.properties.version = FlexibleVersion("9.9.0") + i
                handler = ExtHandlerInstance(eh, "unused")
                os.mkdir(handler.get_base_dir())

            self.assertEqual(no_of_orphaned_packages, TestExtensionCleanup._count_extension_directories(),
                             "Test Setup error - Not enough extension directories")
            exthandlers_handler.run()
            self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "There should be no extension directories in FS")
            self.assertIsNone(protocol.aggregate_status,
                              "Since there's no ExtConfig, we shouldn't even report status as we pull status blob link from ExtConfig")

    def test_cleanup_leaves_failed_extensions(self):
        original_popen = subprocess.Popen

        def mock_fail_popen(*args, **kwargs):
            return original_popen("fail_this_command", **kwargs)

        with self._setup_test_env(mockwiredata.DATA_FILE_EXT_SINGLE) as (exthandlers_handler, protocol, no_of_exts):
            with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", mock_fail_popen):
                exthandlers_handler.run()
                self._assert_ext_handler_status(protocol.aggregate_status, "NotReady",
                                                expected_ext_handler_count=no_of_exts,
                                                version="1.0.0")
                self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                                 "There should still be 1 extension directory in FS")

            # Update incarnation and extension config to uninstall the extension, this should delete the extension
            protocol.mock_wire_data.set_incarnation(2)
            protocol.mock_wire_data.set_extensions_config_state("uninstall")

            protocol.client.update_goal_state()
            exthandlers_handler.run()

            self.assertEqual(0, TestExtensionCleanup._count_packages(), "All packages must be deleted")
            self.assertEqual(0, TestExtensionCleanup._count_extension_directories(),
                             "All extension directories should be removed")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=0,
                                            version="1.0.0")


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
    def setUp(self):
        AgentTestCase.setUp(self)

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
        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(KNOWN_WIRESERVER_IP)
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        handler = get_exthandlers_handler(protocol)

        return handler, protocol

    def _set_up_update_test_and_update_gs(self, patch_command, *args):
        """
        This helper function sets up the Update test by setting up the protocol and ext_handler and asserts the
        ext_handler runs fine the first time before patching a failure command for testing.
        :param patch_command: The patch_command to setup for failure
        :param args: Any additional args passed to the function, needed for creating a mock for handler and protocol
        :return: test_data, exthandlers_handler, protocol
        """
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Ensure initial install and enable is successful
        exthandlers_handler.run()

        self.assertEqual(0, patch_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, update version
        test_data.set_incarnation(2)
        test_data.set_extensions_config_version("1.0.1")
        test_data.set_manifest_version('1.0.1')
        protocol.update_goal_state()

        # Ensure the patched command fails
        patch_command.return_value = "exit 1"

        return test_data, exthandlers_handler, protocol

    @staticmethod
    def _create_extension_handlers_handler(protocol):
        handler = get_exthandlers_handler(protocol)
        return handler

    def test_ext_handler(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.set_incarnation(3)
        test_data.set_extensions_config_version("1.1.1")
        test_data.set_extensions_config_sequence_number(2)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.2.0")
        test_data.set_extensions_config_sequence_number(3)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.set_incarnation(5)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.2.0")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.update_goal_state()

        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_it_should_only_download_extension_manifest_once_per_goal_state(self, *args):

        def _assert_handler_status_and_manifest_download_count(protocol, test_data, manifest_count):
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
            self._assert_ext_status(protocol.report_ext_status, "success", 0)
            self.assertEqual(test_data.call_counts['manifest.xml'], manifest_count,
                             "We should have downloaded extension manifest {0} times".format(manifest_count))

        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        _assert_handler_status_and_manifest_download_count(protocol, test_data, 1)

        for _ in range(5):
            exthandlers_handler.run()
            # The extension manifest should only be downloaded once as incarnation did not change
            _assert_handler_status_and_manifest_download_count(protocol, test_data, 1)

        # Update Incarnation
        test_data.set_incarnation(2)
        protocol.update_goal_state()

        exthandlers_handler.run()
        _assert_handler_status_and_manifest_download_count(protocol, test_data, 2)

        for _ in range(5):
            exthandlers_handler.run()
            # The extension manifest should be downloaded twice now as incarnation changed once
            _assert_handler_status_and_manifest_download_count(protocol, test_data, 2)

    def test_ext_zip_file_packages_removed_in_update_case(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.0.0")

        # Update the package
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        test_data.set_extensions_config_version("1.1.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version="1.0.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.1.0")

        # Update the package second time
        test_data.set_incarnation(3)
        test_data.set_extensions_config_sequence_number(2)
        test_data.set_extensions_config_version("1.2.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version="1.1.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.2.0")

    def test_ext_zip_file_packages_removed_in_uninstall_case(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        extension_version = "1.0.0"

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, extension_version)
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version=extension_version)

        # Test uninstall
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version=extension_version)

    def test_ext_zip_file_packages_removed_in_update_and_uninstall_case(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.0.0")

        # Update the package
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        test_data.set_extensions_config_version("1.1.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version="1.0.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.1.0")

        # Update the package second time
        test_data.set_incarnation(3)
        test_data.set_extensions_config_sequence_number(2)
        test_data.set_extensions_config_version("1.2.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version="1.1.0")
        self._assert_ext_pkg_file_status(expected_to_be_present=True, extension_version="1.2.0")

        # Test uninstall
        test_data.set_incarnation(4)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)
        self._assert_ext_pkg_file_status(expected_to_be_present=False, extension_version="1.2.0")

    def test_ext_handler_no_settings(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_NO_SETTINGS)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0.0")

    def test_ext_handler_no_public_settings(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_NO_PUBLIC)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

    def test_ext_handler_no_ext(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        # Assert no extension handler status
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_handler_sequencing(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

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
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        # Swap the dependency ordering
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"", "dependencyLevel=\"3\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"", "dependencyLevel=\"4\"")
        protocol.update_goal_state()

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
        test_data.set_incarnation(3)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 4)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 3)

        # Test uninstall
        # In the case of uninstall, the last extension to be installed should be
        # the first extension uninstalled. The first extension installed
        # should be the last one uninstalled.
        test_data.set_incarnation(4)
        test_data.set_extensions_config_state("uninstall")

        # Swap the dependency ordering AGAIN
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"3\"", "dependencyLevel=\"6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"4\"", "dependencyLevel=\"5\"")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)
        self.assertEqual(len(exthandlers_handler.ext_handlers.extHandlers), 2)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 6)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[1].properties.extensions[0].dependencyLevel, 5)

    def test_ext_handler_sequencing_default_dependency_level(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)
        self.assertEqual(exthandlers_handler.ext_handlers.extHandlers[0].properties.extensions[0].dependencyLevel, 0)

    def test_ext_handler_sequencing_invalid_dependency_level(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SEQUENCING)
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"",
                                                        "dependencyLevel=\"a6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"",
                                                        "dependencyLevel=\"5b\"")
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

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

        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_MULTIPLE_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()

        status_path = os.path.join(conf.get_lib_dir(), AGENT_STATUS_FILE)
        actual_status_json = json.loads(fileutil.read_file(status_path))

        self.assertEquals(expected_status_json, actual_status_json)

    def test_ext_handler_rollingupgrade(self, *args):
        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_ROLLINGUPGRADE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state changed
        test_data.set_incarnation(2)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test minor version bump
        test_data.set_incarnation(3)
        test_data.set_extensions_config_version("1.1.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test hotfix version bump
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.1.1")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test disable
        test_data.set_incarnation(5)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.1.1")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test re-install
        test_data.set_incarnation(8)
        test_data.set_extensions_config_state("enabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test version bump post-re-install
        test_data.set_incarnation(9)
        test_data.set_extensions_config_version("1.2.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test rollback
        test_data.set_incarnation(10)
        test_data.set_extensions_config_version("1.1.0")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_download_failure_transient(self, mock_add_event, *args):
        original_sleep = time.sleep

        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.download_ext_handler_pkg = Mock(side_effect=ProtocolError)

        exthandlers_handler.run()

        self.assertEquals(0, mock_add_event.call_count)

    def test_it_should_create_extension_events_dir_and_set_handler_environment_only_if_extension_telemetry_enabled(self, *args):

        for enable_extensions in [False, True]:
            tmp_lib_dir = tempfile.mkdtemp(prefix="ExtensionEnabled{0}".format(enable_extensions))
            with patch("azurelinuxagent.common.conf.get_lib_dir", return_value=tmp_lib_dir):
                with patch('azurelinuxagent.ga.exthandlers.is_extension_telemetry_pipeline_enabled',
                           return_value=enable_extensions):
                    # Create new object for each run to force re-installation of extensions as we
                    # only create handler_environment on installation
                    test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_MULTIPLE_EXT)
                    exthandlers_handler, protocol = self._create_mock(test_data, *args)

                    exthandlers_handler.run()
                    self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
                    self._assert_ext_status(protocol.report_ext_status, "success", 0)

                    for ext_handler in exthandlers_handler.ext_handlers.extHandlers:
                        ehi = ExtHandlerInstance(ext_handler, protocol)
                        self.assertEqual(enable_extensions, os.path.exists(ehi.get_extension_events_dir()),
                                         "Events directory incorrectly set")
                        handler_env_json = ehi.get_env_file()
                        with open(handler_env_json, 'r') as env_json:
                            env_data = json.load(env_json)

                        self.assertEqual(enable_extensions, "eventsFolder" in env_data[0]['handlerEnvironment'],
                                         "eventsFolder wrongfully set in HandlerEnvironment.json file")

                        if enable_extensions:
                            self.assertEqual(ehi.get_extension_events_dir(),
                                             env_data[0]['handlerEnvironment']["eventsFolder"],
                                             "Events directory dont match")

            # Clean the File System for the next test run
            if os.path.exists(tmp_lib_dir):
                shutil.rmtree(tmp_lib_dir, ignore_errors=True)

    def test_it_should_not_delete_extension_events_directory_on_extension_uninstall(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        with patch('azurelinuxagent.ga.exthandlers.is_extension_telemetry_pipeline_enabled', return_value=True):
            exthandlers_handler.run()
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
            self._assert_ext_status(protocol.report_ext_status, "success", 0)

            ehi = ExtHandlerInstance(exthandlers_handler.ext_handlers.extHandlers[0], protocol)
            self.assertTrue(os.path.exists(ehi.get_extension_events_dir()), "Events directory should exist")

            # Uninstall extensions now
            test_data.set_extensions_config_state("uninstall")
            test_data.set_incarnation(2)
            protocol.update_goal_state()
            exthandlers_handler.run()
            self.assertTrue(os.path.exists(ehi.get_extension_events_dir()), "Events directory should still exist")

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_report_status_permanent(self, mock_add_event, mock_error_state, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        protocol.get_ext_handler_pkgs = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True

        exthandlers_handler.run()

        self.assertEquals(1, mock_add_event.call_count)
        args, kw = mock_add_event.call_args_list[0]
        self.assertEquals(False, kw['is_success'])
        self.assertTrue("Failed to get ext handler pkgs" in kw['message'])
        self.assertTrue("ProtocolError" in kw['message'])

    @patch('azurelinuxagent.common.event.add_event')
    def test_ext_handler_download_errors_should_be_reported_only_on_new_goal_state(self, mock_add_event, *args):

        def _assert_mock_add_event_call(expected_download_failed_event_count, err_msg_guid):
            event_occurrences = [kw for _, kw in mock_add_event.call_args_list if
                          "Failed to download artifacts: [ExtensionDownloadError] {0}".format(err_msg_guid) in kw['message']]
            self.assertEquals(expected_download_failed_event_count, len(event_occurrences), "Call count do not match")
            self.assertFalse(any([kw['is_success'] for kw in event_occurrences]), "The events should have failed")
            self.assertEqual(expected_download_failed_event_count, len([kw['op'] for kw in event_occurrences]),
                             "Incorrect Operation, all events should be a download errors")

        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        unique_error_message_guid = str(uuid.uuid4())
        protocol.get_ext_handler_pkgs = Mock(side_effect=ExtensionDownloadError(unique_error_message_guid))

        exthandlers_handler.run()
        _assert_mock_add_event_call(expected_download_failed_event_count=1, err_msg_guid=unique_error_message_guid)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0")

        # Re-run exthandler.run without updating the GS and ensure we dont report error
        exthandlers_handler.run()
        _assert_mock_add_event_call(expected_download_failed_event_count=1, err_msg_guid=unique_error_message_guid)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0")

        # Change incarnation and then re-check we report error
        test_data.set_incarnation(2)
        protocol.update_goal_state()

        exthandlers_handler.run()
        _assert_mock_add_event_call(expected_download_failed_event_count=2, err_msg_guid=unique_error_message_guid)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.fileutil')
    def test_ext_handler_io_error(self, mock_fileutil, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        mock_fileutil.write_file.return_value = IOError("Mock IO Error")
        exthandlers_handler.run()

    def test_extension_processing_allowed(self, *args):
        exthandlers_handler = get_exthandlers_handler(Mock())

        # disable extension handling in configuration
        with patch.object(conf, 'get_extensions_enabled', return_value=False):
            self.assertFalse(exthandlers_handler._extension_processing_allowed())

        # enable extension handling in configuration
        with patch.object(conf, "get_extensions_enabled", return_value=True):
            # disable overprovisioning in configuration
            with patch.object(conf, 'get_enable_overprovisioning', return_value=False):
                self.assertTrue(exthandlers_handler._extension_processing_allowed())

            # enable overprovisioning in configuration
            with patch.object(conf, "get_enable_overprovisioning", return_value=True):
                with patch.object(exthandlers_handler.protocol.get_artifacts_profile(), "is_on_hold",
                                  side_effect=[True, False]):
                    # Enable on_hold property in artifact_blob
                    self.assertFalse(exthandlers_handler._extension_processing_allowed())

                    # Disable on_hold property in artifact_blob
                    self.assertTrue(exthandlers_handler._extension_processing_allowed())

    def test_handle_ext_handlers_on_hold_true(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, exthandlers_handler.last_etag = protocol.get_ext_handlers()
        protocol.get_artifacts_profile = MagicMock()
        exthandlers_handler.protocol = protocol

        # Disable extension handling blocking
        exthandlers_handler._extension_processing_allowed = Mock(return_value=False)
        with patch.object(ExtHandlersHandler, 'handle_ext_handlers') as patch_handle_ext_handlers:
            exthandlers_handler.run()
            self.assertEqual(0, patch_handle_ext_handlers.call_count)

        # enable extension handling blocking
        exthandlers_handler._extension_processing_allowed = Mock(return_value=True)
        with patch.object(ExtHandlersHandler, 'handle_ext_handlers') as patch_handle_ext_handlers:
            exthandlers_handler.run()
            self.assertEqual(1, patch_handle_ext_handlers.call_count)

    def test_handle_ext_handlers_on_hold_false(self, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.ext_handlers, etag = protocol.get_ext_handlers()
        exthandlers_handler.protocol = protocol

        # Disable extension handling blocking in the first run and enable in the 2nd run
        with patch.object(exthandlers_handler, '_extension_processing_allowed', side_effect=[False, True]):
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        self._assert_ext_status(protocol.report_ext_status, ValidHandlerStatus.error, 0)

    def test_wait_for_handler_successful_completion_empty_exts(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is no extension in a handler.
        Expected to return True.
        '''
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=None)
        self.assertFalse(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_success_status(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is successful status.
        Expected to return True.
        '''
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        status = "success"

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=status)
        self.assertTrue(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_error_status(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is error status.
        Expected to return False.
        '''
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        status = "error"

        ExtHandlerInstance.get_ext_handling_status = MagicMock(return_value=status)
        self.assertFalse(self._helper_wait_for_handler_successful_completion(exthandlers_handler))

    def test_wait_for_handler_successful_completion_timeout(self, *args):
        '''
        Testing wait_for_handler_successful_completion() when there is non terminal status.
        Expected to return False.
        '''
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
        """
        Testing is_ext_handling_complete() with various input and
        verifying against the expected output values.
        """
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
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
                        datafile = mockwiredata.DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION
                    else:
                        datafile = mockwiredata.DATA_FILE_EXT_INTERNALVERSION
                else:
                    config_version = '1.0.0'
                    decision_version = '1.0.0'
                    if autoupgrade:
                        datafile = mockwiredata.DATA_FILE_EXT_AUTOUPGRADE
                    else:
                        datafile = mockwiredata.DATA_FILE

                _, protocol = self._create_mock(mockwiredata.WireProtocolData(datafile), *args)
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

        _, protocol = self._create_mock(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE), *args)
        version_uri = Mock()
        version_uri.uri = 'http://mock-goal-state/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'

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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

        # test status is reported, but extensions are not processed
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        exthandlers_handler.run()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_extensions_deleted(self, *args):
        # Ensure initial enable is successful
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_DELETION)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Update incarnation, simulate new extension version and old one deleted
        test_data.set_incarnation(2)
        test_data.set_extensions_config_version("1.0.1")
        test_data.set_manifest_version('1.0.1')
        protocol.update_goal_state()

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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        # Ensure initial install and enable is successful, but disable fails
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        patch_get_disable_command.call_count = 0
        patch_get_disable_command.return_value = "exit.sh 1"

        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

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
        # Ensure initial install and enable is successful, but disable fails
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        patch_get_disable_command.call_count = 0
        patch_get_disable_command.return_value = "exit 1"

        exthandlers_handler.run()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self.assertEqual(1, patch_get_disable_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self.assertEqual(1, patch_handle_ext_handler_error.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_uninstall_failure(self, patch_get_uninstall_command, *args):
        """
        When extension uninstall fails, the operation should not be retried.
        """
        # Ensure initial install and enable is successful, but uninstall fails
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)
        patch_get_uninstall_command.call_count = 0
        patch_get_uninstall_command.return_value = "exit 1"

        exthandlers_handler.run()

        self.assertEqual(0, patch_get_uninstall_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Next incarnation, disable extension
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

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
    def test_extension_upgrade_failure_when_new_version_update_fails(self, patch_get_update_command, *args):
        """
        When the update command of the new extension fails, it should result in the new extension failed and the
        old extension disabled. On the next goal state, the entire upgrade scenario should be retried (once),
        meaning the download, initialize and update are called on the new extension.
        Note: we don't re-download the zip since it wasn't cleaned up in the previous goal state (we only clean up
        NotInstalled handlers), so we just re-use the existing zip of the new extension.
        """
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_update_command, *args)
        extension_name = exthandlers_handler.ext_handlers.extHandlers[0].name
        extension_calls = []
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Maintain an internal list of invoked commands of the test extension to assert on later
            if extension_name in args[0]:
                extension_calls.append(args[0])
            return original_popen(*args, **kwargs)

        with patch('azurelinuxagent.common.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            exthandlers_handler.run()
            update_command_count = len([extension_call for extension_call in extension_calls
                                        if patch_get_update_command.return_value in extension_call])
            enable_command_count = len([extension_call for extension_call in extension_calls
                                        if "-enable" in extension_call])

            self.assertEquals(1, update_command_count)
            self.assertEquals(0, enable_command_count)

            # We report the failure of the new extension version
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

            # Ensure we are processing the same goal state only once
            loop_run = 5
            for x in range(loop_run):
                exthandlers_handler.run()

            update_command_count = len([extension_call for extension_call in extension_calls
                                        if patch_get_update_command.return_value in extension_call])
            enable_command_count = len([extension_call for extension_call in extension_calls
                                        if "-enable" in extension_call])
            self.assertEquals(1, update_command_count)
            self.assertEquals(0, enable_command_count)

            # If the incarnation number changes (there's a new goal state), ensure we go through the entire upgrade
            # process again.
            test_data.set_incarnation(3)
            protocol.update_goal_state()

            exthandlers_handler.run()

            update_command_count = len([extension_call for extension_call in extension_calls
                                        if patch_get_update_command.return_value in extension_call])
            enable_command_count = len([extension_call for extension_call in extension_calls
                                        if "-enable" in extension_call])
            self.assertEquals(2, update_command_count)
            self.assertEquals(0, enable_command_count)

            # We report the failure of the new extension version
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_failure_when_prev_version_disable_fails(self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command, *args)

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
    def test_extension_upgrade_failure_when_prev_version_disable_fails_and_recovers_on_next_incarnation(self, patch_get_disable_command,
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
            test_data.set_incarnation(3)
            protocol.update_goal_state()

            # Ensure disable won't fail by making launch_command a no-op
            with patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.launch_command') as patch_launch_command:
                exthandlers_handler.run()
                self.assertEqual(2, patch_get_disable_command.call_count)
                self.assertEqual(1, patch_get_enable_command.call_count)
                self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_failure_when_prev_version_disable_fails_incorrect_zip(self, patch_get_disable_command,
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
    def test_old_handler_reports_failure_on_disable_fail_on_update(self, patch_get_disable_command, *args):
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
            test_data.set_incarnation(3)
            protocol.update_goal_state()

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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_MULTIPLE_EXT)
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

        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_SINGLE)
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
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(KNOWN_WIRESERVER_IP)
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()
        protocol.get_artifacts_profile = MagicMock()

        handler = get_exthandlers_handler(protocol)
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
        monitor_handler = get_monitor_handler()

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        mock_crypt_util.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(KNOWN_WIRESERVER_IP)
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        ext_handler = get_exthandlers_handler(protocol)

        protocol_util = get_protocol_util()
        protocol_util.get_protocol = Mock(return_value=protocol)
        monitor_handler.protocol_util = Mock(return_value=protocol_util)
        return ext_handler, monitor_handler, protocol

    @attr('requires_sudo')
    def test_ext_handler_with_cgroup_enabled(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, _, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.set_incarnation(3)
        test_data.set_extensions_config_version("1.1.1")
        test_data.set_extensions_config_sequence_number(2)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.2.0")
        test_data.set_extensions_config_sequence_number(3)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.set_incarnation(5)
        test_data.set_extensions_config_state("disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.2.0")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.set_extensions_config_state("uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)


    @attr('requires_sudo')
    def test_ext_handler_with_systemd_cgroup_enabled(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        from azurelinuxagent.common.cgroupapi import CGroupsApi
        print(CGroupsApi._is_systemd())

        # Test enable scenario.
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        exthandlers_handler, _, protocol = self._create_mock(test_data, *args)

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 1)

        # Test hotfix
        test_data.set_incarnation(3)
        test_data.ext_conf = test_data.ext_conf.replace("1.0.0", "1.1.1")
        test_data.set_extensions_config_sequence_number(2)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_ext_status, "success", 2)

        # Test upgrade
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.2.0")
        test_data.set_extensions_config_sequence_number(3)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_ext_status, "success", 3)

        # Test disable
        test_data.set_incarnation(5)
        test_data.ext_conf = test_data.ext_conf.replace("enabled", "disabled")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.2.0")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.ext_conf = test_data.ext_conf.replace("disabled", "uninstall")
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.update_goal_state()

        exthandlers_handler.run()

        self._assert_no_handler_status(protocol.report_vm_status)


class TestExtensionUpdateOnFailure(ExtensionTestCase):
    
    def setUp(self):
        AgentTestCase.setUp(self)
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.0001))
        self.mock_sleep.start()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

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

    @staticmethod
    def _do_upgrade_scenario(firstVersionActor, secondVersionActor):
        """
        Given the provided ExtensionActor objects, installs the first and then attempts
        to update to the second. StatusBlobs and command invocations for each actor can
        be checked with {actor}.statusBlobs and {actor}.get_command({command_name})
        respectively.

        Note that this method assumes the firstVersionActor's install command should
        succeed. Don't use this method if your test is attempting to emulate a fresh install
        (i.e. not an upgrade) with a failing installCommand.
        """
        
        with get_protocol_and_handler(firstVersionActor) as (protocol, exthandlers_handler):

            # Run the handler with only the first version to install it
            with firstVersionActor.patch_popen():
                exthandlers_handler.run()
            
            # Verify the extension was picked up correctly.
            # NOTE: this won't work for tests that want install to fail.
            firstVersionActor.get_command("installCommand").assert_called_once()
            firstVersionActor.get_command("enableCommand").assert_called_once()

            # Update to the second goal state incarnation, including the updated actor this time
            update_extension_actors(protocol, 2, firstVersionActor, secondVersionActor)

            # Run the handler a second time on the updated goal state (including the new extension version)
            with firstVersionActor.patch_popen():
                with secondVersionActor.patch_popen():
                    exthandlers_handler.run()
    
    
    def test_enabled_ext_should_be_disabled_at_ver_update(self):

        first_ext = get_extension_actor()
        second_ext = get_extension_actor(version="1.1.0")

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()
        second_ext.get_command("enableCommand").assert_called_once()


    def test_non_enabled_ext_should_not_be_disabled_at_ver_update(self):

        first_ext = get_extension_actor(enableAction=Actions.FailAction)
        second_ext = get_extension_actor(version="1.1.0")

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        second_ext.get_command("installCommand").assert_called_once()
        second_ext.get_command("enableCommand").assert_called_once()
        first_ext.get_command("disableCommand").assert_not_called()
        

    def test_disable_failed_env_variable_should_be_set_for_update_cmd_when_continue_on_update_failure_is_true(self):
        exit_code = uuid.uuid4()    # Generate a unique UUID for highest strictness.
        unique_fail = lambda *args, **kwargs: exit_code

        first_ext = get_extension_actor(disableAction=unique_fail)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=True)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        first_ext.get_command("disableCommand").assert_called_once()            
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()
        
        _, kwargs = second_ext.get_command("updateCommand").call_args

        assert kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") == str(exit_code)


    def test_uninstall_failed_env_variable_should_set_for_install_when_continue_on_update_failure_is_true(self):

        exit_code = uuid.uuid4()    # Generate a unique UUID for highest strictness.
        unique_fail = lambda *args, **kwargs: exit_code

        first_ext = get_extension_actor(uninstallAction=unique_fail)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=True)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        first_ext.get_command("disableCommand").assert_called_once()            
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()
        
        _, kwargs = second_ext.get_command("installCommand").call_args

        assert kwargs.get("env", {}).get(ExtCommandEnvVariable.UninstallReturnCode, "") == str(exit_code)


    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_disable_failure(self, *args):
        exit_code = uuid.uuid4()    # Generate a unique UUID for highest strictness.
        unique_fail = lambda *args, **kwargs: exit_code

        first_ext = get_extension_actor(disableAction=unique_fail)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=False)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)
            
        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_not_called()
        first_ext.get_command("uninstallCommand").assert_not_called()
        second_ext.get_command("installCommand").assert_not_called()

        status_msg_contains = lambda msg, *strs: all(s in msg for s in strs)

        # TODO: For now, we're just making sure the correct status blob exists (i.e. with "any"), not that it is the only
        # TODO: status blob reported (i.e. with "all", possibly?). Is the behavior that this assumes invariant?

        assert any(
            status_msg_contains(message, str(exit_code))
            for message in [
                statusBlob.get("formattedMessage", {}).get("message", "")
                for statusBlob in second_ext.statusBlobs
            ]
        )


    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_uninstall_failure(self, *args):
        exit_code = uuid.uuid4()    # Generate a unique UUID for highest strictness.
        unique_fail = lambda *args, **kwargs: exit_code

        first_ext = get_extension_actor(uninstallAction=unique_fail)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=False)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)
            
        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_not_called()

        status_msg_contains = lambda msg, *strs: all(s in msg for s in strs)

        # TODO: For now, we're just making sure the correct status blob exists (i.e. with "any"), not that it is the only
        # TODO: status blob reported (i.e. with "all", possibly?). Is the behavior that this assumes invariant?

        assert any(
            status_msg_contains(message, str(exit_code))
            for message in [
                statusBlob.get("formattedMessage", {}).get("message", "")
                for statusBlob in second_ext.statusBlobs
            ]
        )

    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_true_on_disable_and_update_failure(self, *args):
        exit_codes = { "disable": uuid.uuid4(), "update": uuid.uuid4() }

        fail_disable = lambda *args, **kwargs: exit_codes["disable"]
        fail_update = lambda *args, **kwargs: exit_codes["update"]

        first_ext = get_extension_actor(disableAction=fail_disable)
        second_ext = get_extension_actor(updateAction=fail_update, version="1.1.0", continueOnUpdateFailure=True)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)
            
        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_not_called()
        second_ext.get_command("installCommand").assert_not_called()

        status_msg_contains = lambda msg, *strs: all(s in msg for s in strs)

        # TODO: For now, we're just making sure the correct status blob exists (i.e. with "any"), not that it is the only
        # TODO: status blob reported (i.e. with "all", possibly?). Is the behavior that this assumes invariant?
        
        assert any(
            status_msg_contains(message, str(exit_codes["update"])) # We check explicitly for the update code.
            for message in [
                statusBlob.get("formattedMessage", {}).get("message", "")
                for statusBlob in second_ext.statusBlobs
            ]
        )

    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_true_on_uninstall_and_install_failure(self, *args):
        exit_codes = { "install": uuid.uuid4(), "uninstall": uuid.uuid4() }

        fail_install = lambda *args, **kwargs: exit_codes["install"]
        fail_uninstall = lambda *args, **kwargs: exit_codes["uninstall"]

        first_ext = get_extension_actor(uninstallAction=fail_uninstall)
        second_ext = get_extension_actor(installAction=fail_install, version="1.1.0", continueOnUpdateFailure=True)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)
            
        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()

        status_msg_contains = lambda msg, *strs: all(s in msg for s in strs)

        # TODO: For now, we're just making sure the correct status blob exists (i.e. with "any"), not that it is the only
        # TODO: status blob reported (i.e. with "all", possibly?). Is the behavior that this assumes invariant?
        
        assert any(
            status_msg_contains(message, str(exit_codes["install"])) # We check explicitly for the update code.
            for message in [
                statusBlob.get("formattedMessage", {}).get("message", "")
                for statusBlob in second_ext.statusBlobs
            ]
        )


    @patch("azurelinuxagent.common.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_env_variable_should_not_set_when_continue_on_update_failure_is_false(self, *args):
        
        # TODO: This test case seems covered by two above tests in this same suite: 
        # TODO: test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_{disable, update}_failure
        # TODO: Can we safely remove this test?

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

    def test_failed_env_variables_should_be_set_from_within_extension_commands(self, *args):
        """
        This test will test from the perspective of the extensions command weather the env variables are
        being set for those processes
        """
        exit_codes = { "disable": uuid.uuid4(), "uninstall": uuid.uuid4() }

        fail_disable = lambda *args, **kwargs: exit_codes["disable"]
        fail_uninstall = lambda *args, **kwargs: exit_codes["uninstall"]

        first_ext = get_extension_actor(disableAction=fail_disable, uninstallAction=fail_uninstall)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=True)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()

        _, update_kwargs = second_ext.get_command("updateCommand").call_args
        _, install_kwargs = second_ext.get_command("installCommand").call_args

        # TODO: Is it good enough to just check the variable name exists? Or should we
        # TODO: also check its value? (below)

        # Ensure we're checking variables for update scenario
        assert update_kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") == str(exit_codes["disable"])
        assert update_kwargs.get("env", {}).get(ExtCommandEnvVariable.UninstallReturnCode, "") != str(exit_codes["uninstall"])
        self.assertTrue(ExtCommandEnvVariable.ExtensionPath in update_kwargs['env'] and
                        ExtCommandEnvVariable.ExtensionVersion in update_kwargs['env'])

        # Ensure we're checking variables for install scenario
        assert install_kwargs.get("env", {}).get(ExtCommandEnvVariable.UninstallReturnCode, "") == str(exit_codes["uninstall"])
        assert install_kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") != str(exit_codes["disable"])
        self.assertTrue(ExtCommandEnvVariable.ExtensionPath in install_kwargs['env'] and
                        ExtCommandEnvVariable.ExtensionVersion in install_kwargs['env'])
        

    def test_correct_exit_code_should_set_on_disable_cmd_failure(self):
        exit_code = uuid.uuid4()
        disable_fail = lambda *args, **kwargs: exit_code

        first_ext = get_extension_actor(disableAction=disable_fail)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=True, updateMode="UpdateWithoutInstall")

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)

        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_not_called()

        _, update_kwargs = second_ext.get_command("updateCommand").call_args

        assert update_kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") == str(exit_code)


    def test_timeout_code_should_set_on_cmd_timeout(self):

        # Return None to every poll, forcing a timeout after 900 seconds (actually very quick because sleep(*) is mocked)
        force_timeout = lambda *args, **kwargs: None

        first_ext = get_extension_actor(disableAction=force_timeout, uninstallAction=force_timeout)
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=True)
        
        # TODO: Should these patches be built in to the ExtensionActor class?
        with patch("os.killpg"):
            with patch("os.getpgid") as mock_getpid:
                TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)


        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()

        _, update_kwargs = second_ext.get_command("updateCommand").call_args
        _, install_kwargs = second_ext.get_command("installCommand").call_args

        # Verify both commands are reported as timeouts.
        assert update_kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") == str(ExtensionErrorCodes.PluginHandlerScriptTimedout)
        assert install_kwargs.get("env", {}).get(ExtCommandEnvVariable.UninstallReturnCode, "") == str(ExtensionErrorCodes.PluginHandlerScriptTimedout)


    def test_success_code_should_set_in_env_variables_on_cmd_success(self):
        first_ext = get_extension_actor()
        second_ext = get_extension_actor(version="1.1.0", continueOnUpdateFailure=False)

        TestExtensionUpdateOnFailure._do_upgrade_scenario(first_ext, second_ext)
        
        first_ext.get_command("disableCommand").assert_called_once()
        second_ext.get_command("updateCommand").assert_called_once()
        first_ext.get_command("uninstallCommand").assert_called_once()
        second_ext.get_command("installCommand").assert_called_once()

        _, update_kwargs = second_ext.get_command("updateCommand").call_args
        _, install_kwargs = second_ext.get_command("installCommand").call_args

        assert update_kwargs.get("env", {}).get(ExtCommandEnvVariable.DisableReturnCode, "") == "0"
        assert install_kwargs.get("env", {}).get(ExtCommandEnvVariable.UninstallReturnCode, "") == "0"


@patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
class TestCollectExtensionStatus(ExtensionTestCase):
    def setUp(self):
        ExtensionTestCase.setUp(self)
        self.lib_dir = tempfile.mkdtemp()

    def _setup_extension_for_validating_collect_ext_status(self, mock_lib_dir, status_file, *args):
        handler_name = "TestHandler"
        handler_version = "1.0.0"
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(os.path.join(self.lib_dir, handler_name + "-" + handler_version, "config"))
        fileutil.mkdir(os.path.join(self.lib_dir, handler_name + "-" + handler_version, "status"))
        shutil.copy(os.path.join(data_dir, "ext", status_file),
                    os.path.join(self.lib_dir, handler_name + "-" + handler_version, "status", "0.status"))
        shutil.copy(tempfile.mkstemp(prefix="test-file")[1],
                    os.path.join(self.lib_dir, handler_name + "-" + handler_version, "config", "0.settings"))

        with mock_wire_protocol(DATA_FILE) as protocol:
            exthandler = ExtHandler(name=handler_name)
            exthandler.properties.version = handler_version
            extension = Extension(name=handler_name, sequenceNumber=0)
            exthandler.properties.extensions.append(extension)

            return ExtHandlerInstance(exthandler, protocol), extension

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status(self, mock_lib_dir, *args):
        """
        This test validates that collect_ext_status correctly picks up the status file (sample-status.json) and then
        parses it correctly.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status.json", *args)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertEqual(ext_status.message, "Aenean semper nunc nisl, vitae sollicitudin felis consequat at. In "
                                             "lobortis elementum sapien, non commodo odio semper ac.")
        self.assertEqual(ext_status.status, ValidHandlerStatus.success)

        self.assertEqual(len(ext_status.substatusList), 1)
        sub_status = ext_status.substatusList[0]
        self.assertEqual(sub_status.code, "0")
        self.assertEqual(sub_status.message, None)
        self.assertEqual(sub_status.status, ValidHandlerStatus.success)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_very_large_status_message(self, mock_lib_dir, *args):
        """
        Testing collect_ext_status() with a very large status file (>128K) to see if it correctly parses the status
        without generating a really large message.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status-very-large.json",
                                                                                           *args)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        # [TRUNCATED] comes from azurelinuxagent.ga.exthandlers._TRUNCATED_SUFFIX
        self.assertRegex(ext_status.message, r"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum non "
                                             r"lacinia urna, sit .*\[TRUNCATED\]")
        self.maxDiff = None
        self.assertEqual(ext_status.status, ValidHandlerStatus.success)
        self.assertEqual(len(ext_status.substatusList), 1) # NUM OF SUBSTATUS PARSED
        for sub_status in ext_status.substatusList:
            self.assertRegex(sub_status.name, '\[\{"status"\: \{"status": "success", "code": "1", "snapshotInfo": '
                                              '\[\{"snapshotUri":.*')
            self.assertEqual(0, sub_status.code)
            self.assertRegex(sub_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
                                                 "non lacinia urna, sit amet venenatis orci.*")
            self.assertEqual(sub_status.status, ValidHandlerStatus.success)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_very_large_status_file_with_multiple_substatus_nodes(self, mock_lib_dir, *args):
        """
        Testing collect_ext_status() with a very large status file (>128K) to see if it correctly parses the status
        without generating a really large message. This checks if the multiple substatus messages are correctly parsed
        and truncated.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(
            mock_lib_dir, "sample-status-very-large-multiple-substatuses.json", *args)  # ~470K bytes.
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                                             "Vestibulum non lacinia urna, sit .*")
        self.assertEqual(ext_status.status, ValidHandlerStatus.success)
        self.assertEqual(len(ext_status.substatusList), 12)  # The original file has 41 substatus nodes.
        for sub_status in ext_status.substatusList:
            self.assertRegex(sub_status.name, '\[\{"status"\: \{"status": "success", "code": "1", "snapshotInfo": '
                                              '\[\{"snapshotUri":.*')
            self.assertEqual(0, sub_status.code)
            self.assertRegex(sub_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
                                                 "non lacinia urna, sit amet venenatis orci.*")
            self.assertEqual(ValidHandlerStatus.success, sub_status.status)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_read_file_read_exceptions(self, mock_lib_dir, *args):
        """
        Testing collect_ext_status to validate the readfile exceptions.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status.json", *args)
        original_read_file = read_file

        def mock_read_file(file, *args, **kwargs):
            expected_status_file_path = os.path.join(self.lib_dir,
                                                     ext_handler_i.ext_handler.name + "-" +
                                                     ext_handler_i.ext_handler. properties.version,
                                                     "status", "0.status")
            if file == expected_status_file_path:
                raise IOError("No such file or directory: {0}".format(expected_status_file_path))
            else:
                original_read_file(file, *args, **kwargs)

        with patch('azurelinuxagent.common.utils.fileutil.read_file', mock_read_file) as patch_read_file:
            ext_status = ext_handler_i.collect_ext_status(extension)

            self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginUnknownFailure)
            self.assertEqual(ext_status.configurationAppliedTime, None)
            self.assertEqual(ext_status.operation, None)
            self.assertEqual(ext_status.sequenceNumber, 0)
            self.assertRegex(ext_status.message, r".*We couldn't read any status for {0}-{1} extension, for the "
                                                 r"sequence number {2}. It failed due to".
                             format("TestHandler", "1.0.0", 0))
            self.assertEqual(ext_status.status, ValidHandlerStatus.error)
            self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_json_exceptions(self, mock_lib_dir, *args):
        """
        Testing collect_ext_status() with a malformed json status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                        "sample-status-invalid-format-emptykey-line7.json", *args)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSettingsStatusInvalid)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, r".*The status reported by the extension {0}-{1}\(Sequence number {2}\), "
                                             "was in an incorrect format and the agent could not parse it correctly."
                                             " Failed due to.*".
                         format("TestHandler", "1.0.0", 0))
        self.assertEqual(ext_status.status, ValidHandlerStatus.error)
        self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_parse_ext_status_exceptions(self, mock_lib_dir, *args):
        """
        Testing collect_ext_status() with a malformed json status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                        "sample-status-invalid-status-no-status-status-key.json", *args)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSettingsStatusInvalid)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, "Could not get a valid status from the extension {0}-{1}. "
                                             "Encountered the following error".format("TestHandler", "1.0.0"))
        self.assertEqual(ext_status.status, ValidHandlerStatus.error)
        self.assertEqual(len(ext_status.substatusList), 0)


if __name__ == '__main__':
    unittest.main()
