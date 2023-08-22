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
import datetime
import glob
import json
import os.path
import random
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from azurelinuxagent.common import conf
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_extensions, \
    get_agent_supported_features_list_for_crp
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.datacontract import get_properties
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.fileutil import read_file
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO, AGENT_NAME, \
    AGENT_VERSION
from azurelinuxagent.common.exception import ResourceGoneError, ExtensionDownloadError, ProtocolError, \
    ExtensionErrorCodes, ExtensionError, GoalStateAggregateStatusCodes
from azurelinuxagent.common.protocol.restapi import ExtensionSettings, Extension, ExtHandlerStatus, \
    ExtensionStatus, ExtensionRequestedState
from azurelinuxagent.common.protocol import wire
from azurelinuxagent.common.protocol.wire import WireProtocol, InVMArtifactsProfile
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP

from azurelinuxagent.ga.exthandlers import ExtHandlerInstance, migrate_handler_state, \
    get_exthandlers_handler, ExtCommandEnvVariable, HandlerManifest, NOT_RUN, \
    ExtensionStatusValue, HANDLER_COMPLETE_NAME_PATTERN, HandlerEnvironment, GoalStateStatus

from tests.lib import wire_protocol_data
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.wire_protocol_data import DATA_FILE, DATA_FILE_EXT_ADDITIONAL_LOCATIONS
from tests.lib.tools import AgentTestCase, data_dir, MagicMock, Mock, patch, mock_sleep
from tests.lib.extension_emulator import Actions, ExtensionCommandNames, extension_emulator, \
    enable_invocations, generate_put_handler

# Mocking the original sleep to reduce test execution time
SLEEP = time.sleep


SUCCESS_CODE_FROM_STATUS_FILE = 1


def do_not_run_test():
    return True


def raise_system_exception():
    raise Exception


def raise_ioerror(*args):  # pylint: disable=unused-argument
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
        return re.match(HANDLER_COMPLETE_NAME_PATTERN, os.path.basename(path)) is not None

    def _assert_ext_handler_status(self, aggregate_status, expected_status, version, expected_ext_handler_count=0,
                                   verify_ext_reported=True):
        self.assertIsNotNone(aggregate_status, "Aggregate status should not be None")
        handler_statuses = aggregate_status['aggregateStatus']['handlerAggregateStatus']
        self.assertEqual(expected_ext_handler_count, len(handler_statuses),
                         "All ExtensionHandlers: {0}".format(handler_statuses))
        for ext_handler_status in handler_statuses:
            debug_info = "ExtensionHandler: {0}".format(ext_handler_status)
            self.assertEqual(expected_status, ext_handler_status['status'], debug_info)
            self.assertEqual(version, ext_handler_status['handlerVersion'], debug_info)
            if verify_ext_reported:
                self.assertIn("runtimeSettingsStatus", ext_handler_status, debug_info)
        return

    @contextlib.contextmanager
    def _setup_test_env(self, test_data):
        with mock_wire_protocol(test_data) as protocol:

            def mock_http_put(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            protocol.aggregate_status = None
            protocol.set_http_handlers(http_put_handler=mock_http_put)
            no_of_extensions = protocol.mock_wire_data.get_no_of_plugins_in_extension_config()
            exthandlers_handler = get_exthandlers_handler(protocol)
            yield exthandlers_handler, protocol, no_of_extensions

    def test_cleanup_leaves_installed_extensions(self):
        with self._setup_test_env(wire_protocol_data.DATA_FILE_MULTIPLE_EXT) as (exthandlers_handler, protocol, no_of_exts):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "No of extension directories doesnt match the no of extensions in GS")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=no_of_exts,
                                            version="1.0.0")

    def test_cleanup_removes_uninstalled_extensions(self):
        with self._setup_test_env(wire_protocol_data.DATA_FILE_MULTIPLE_EXT) as (exthandlers_handler, protocol, no_of_exts):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=no_of_exts,
                                            version="1.0.0")

            # Update incarnation and extension config
            protocol.mock_wire_data.set_incarnation(2)
            protocol.mock_wire_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)

            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(0, TestExtensionCleanup._count_packages(), "All packages must be deleted")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=0,
                                            version="1.0.0")
            self.assertEqual(0, TestExtensionCleanup._count_extension_directories(), "All extension directories should be removed")

    def test_cleanup_removes_orphaned_packages(self):
        data_file = wire_protocol_data.DATA_FILE_NO_EXT.copy()
        data_file["ext_conf"] = "wire/ext_conf_no_extensions-no_status_blob.xml"

        no_of_orphaned_packages = 5
        with self._setup_test_env(data_file) as (exthandlers_handler, protocol, no_of_exts):
            self.assertEqual(no_of_exts, 0, "Test setup error - Extensions found in ExtConfig")

            # Create random extension directories
            for i in range(no_of_orphaned_packages):
                eh = Extension(name='Random.Extension.ShouldNot.Be.There')
                eh.version = FlexibleVersion("9.9.0") + i
                handler = ExtHandlerInstance(eh, "unused")
                os.mkdir(handler.get_base_dir())

            self.assertEqual(no_of_orphaned_packages, TestExtensionCleanup._count_extension_directories(),
                             "Test Setup error - Not enough extension directories")
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "There should be no extension directories in FS")
            self.assertIsNone(protocol.aggregate_status,
                              "Since there's no ExtConfig, we shouldn't even report status as we pull status blob link from ExtConfig")

    def test_cleanup_leaves_failed_extensions(self):
        original_popen = subprocess.Popen

        def mock_fail_popen(*args, **kwargs):  # pylint: disable=unused-argument
            return original_popen("fail_this_command", **kwargs)

        with self._setup_test_env(wire_protocol_data.DATA_FILE_EXT_SINGLE) as (exthandlers_handler, protocol, no_of_exts):
            with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", mock_fail_popen):
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                self._assert_ext_handler_status(protocol.aggregate_status, "NotReady",
                                                expected_ext_handler_count=no_of_exts,
                                                version="1.0.0", verify_ext_reported=False)
                self.assertEqual(no_of_exts, TestExtensionCleanup._count_extension_directories(),
                                 "There should still be 1 extension directory in FS")

            # Update incarnation and extension config to uninstall the extension, this should delete the extension
            protocol.mock_wire_data.set_incarnation(2)
            protocol.mock_wire_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)

            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(0, TestExtensionCleanup._count_packages(), "All packages must be deleted")
            self.assertEqual(0, TestExtensionCleanup._count_extension_directories(),
                             "All extension directories should be removed")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=0,
                                            version="1.0.0")

    def test_it_should_report_and_cleanup_only_if_gs_supported(self):

        def assert_gs_aggregate_status(seq_no, status, code):
            gs_status = protocol.aggregate_status['aggregateStatus']['vmArtifactsAggregateStatus']['goalStateAggregateStatus']
            self.assertEqual(gs_status['inSvdSeqNo'], seq_no, "Seq number not matching")
            self.assertEqual(gs_status['code'], code, "The error code not matching")
            self.assertEqual(gs_status['status'], status, "The status not matching")

        def assert_extension_seq_no(expected_seq_no):
            for handler_status in protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']:
                self.assertEqual(expected_seq_no, handler_status['runtimeSettingsStatus']['sequenceNumber'],
                                 "Sequence number mismatch")

        with self._setup_test_env(wire_protocol_data.DATA_FILE_MULTIPLE_EXT) as (exthandlers_handler, protocol, orig_no_of_exts):
            # Run 1 - GS has no required features and contains 5 extensions
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self.assertEqual(orig_no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "No of extension directories doesnt match the no of extensions in GS")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=orig_no_of_exts,
                                            version="1.0.0")
            assert_gs_aggregate_status(seq_no='1', status=GoalStateStatus.Success,
                                       code=GoalStateAggregateStatusCodes.Success)
            assert_extension_seq_no(expected_seq_no=0)

            # Run 2 - Change the GS to one with Required features not supported by the agent
            # This ExtensionConfig has 1 extension - ExampleHandlerLinuxWithRequiredFeatures
            protocol.mock_wire_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_REQUIRED_FEATURES)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.mock_wire_data.set_extensions_config_sequence_number(random.randint(10, 100))
            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self.assertGreater(orig_no_of_exts, 1, "No of extensions to check should be > 1")
            self.assertEqual(orig_no_of_exts, TestExtensionCleanup._count_extension_directories(),
                             "No of extension directories should not be changed")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=orig_no_of_exts,
                                            version="1.0.0")
            assert_gs_aggregate_status(seq_no='2', status=GoalStateStatus.Failed,
                                       code=GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures)
            # Since its an unsupported GS, we should report the last state of extensions
            assert_extension_seq_no(0)
            # assert the extension in the new Config was not reported as that GS was not executed
            self.assertTrue(any('ExampleHandlerLinuxWithRequiredFeatures' not in ext_handler_status['handlerName'] for
                                ext_handler_status in
                                protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                            "Unwanted handler found in status reporting")

            # Run 3 - Run a GS with no Required Features and ensure we execute all extensions properly
            # This ExtensionConfig has 1 extension - OSTCExtensions.ExampleHandlerLinux
            protocol.mock_wire_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
            protocol.mock_wire_data.set_incarnation(3)
            extension_seq_no = random.randint(10, 100)
            protocol.mock_wire_data.set_extensions_config_sequence_number(extension_seq_no)
            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self.assertEqual(1, TestExtensionCleanup._count_extension_directories(),
                             "No of extension directories should not be changed")
            self._assert_ext_handler_status(protocol.aggregate_status, "Ready", expected_ext_handler_count=1,
                                            version="1.0.0")
            assert_gs_aggregate_status(seq_no='3', status=GoalStateStatus.Success,
                                       code=GoalStateAggregateStatusCodes.Success)
            assert_extension_seq_no(expected_seq_no=extension_seq_no)
            # Only OSTCExtensions.ExampleHandlerLinux extension should be reported
            self.assertEqual('OSTCExtensions.ExampleHandlerLinux',
                             protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus'][0]['handlerName'],
                             "Expected handler not found in status reporting")


class TestHandlerStateMigration(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        handler_name = "Not.A.Real.Extension"
        handler_version = "1.2.3"

        self.ext_handler = Extension(handler_name)
        self.ext_handler.version = handler_version
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

        self.assertEqual(self.ext_handler_i.get_handler_state(), self.handler_state)
        self.assertEqual(
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
        self.assertNotEqual(state, self.handler_state)
        self.assertNotEqual(status, self.handler_status.status)
        self.assertNotEqual(code, self.handler_status.code)
        self.assertNotEqual(message, self.handler_status.message)

        self.ext_handler_i.set_handler_state(state)
        self.ext_handler_i.set_handler_status(status=status, code=code, message=message)

        migrate_handler_state()

        self.assertEqual(self.ext_handler_i.get_handler_state(), state)
        handler_status = self.ext_handler_i.get_handler_status()
        self.assertEqual(handler_status.status, status)
        self.assertEqual(handler_status.code, code)
        self.assertEqual(handler_status.message, message)
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
        except Exception as e:  # pylint: disable=unused-variable
            self.fail("set_handler_status threw an exception")

    @patch("shutil.move", side_effect=Exception)
    def test_migration_ignores_move_errors(self, shutil_mock):  # pylint: disable=unused-argument
        self._prepare_handler_state()
        self._prepare_handler_config()

        try:
            migrate_handler_state()
        except Exception as e:
            self.assertTrue(False, "Unexpected exception: {0}".format(str(e)))  # pylint: disable=redundant-unittest-assert
        return

    @patch("shutil.rmtree", side_effect=Exception)
    def test_migration_ignores_tree_remove_errors(self, shutil_mock):  # pylint: disable=unused-argument
        self._prepare_handler_state()
        self._prepare_handler_config()

        try:
            migrate_handler_state()
        except Exception as e:
            self.assertTrue(False, "Unexpected exception: {0}".format(str(e)))  # pylint: disable=redundant-unittest-assert
        return

class TestExtensionBase(AgentTestCase):
    def _assert_handler_status(self, report_vm_status, expected_status,
                               expected_ext_count, version,
                               expected_handler_name="OSTCExtensions.ExampleHandlerLinux", expected_msg=None):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args  # pylint: disable=unused-variable
        vm_status = args[0]
        self.assertNotEqual(0, len(vm_status.vmAgent.extensionHandlers))
        handler_status = next(
            status for status in vm_status.vmAgent.extensionHandlers if status.name == expected_handler_name)
        self.assertEqual(expected_status, handler_status.status, get_properties(handler_status))
        self.assertEqual(expected_handler_name, handler_status.name)
        self.assertEqual(version, handler_status.version)
        self.assertEqual(expected_ext_count, len([ext_handler for ext_handler in vm_status.vmAgent.extensionHandlers if
                                                  ext_handler.name == expected_handler_name and ext_handler.extension_status is not None]))

        if expected_msg is not None:
            self.assertIn(expected_msg, handler_status.message)


# Deprecated. New tests should be added to the TestExtension class
@patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtension_Deprecated(TestExtensionBase):
    def setUp(self):
        AgentTestCase.setUp(self)

    def _assert_ext_pkg_file_status(self, expected_to_be_present=True, extension_version="1.0.0",
                                    extension_handler_name="OSTCExtensions.ExampleHandlerLinux"):
        zip_file_format = "{0}__{1}.zip"
        if expected_to_be_present:
            self.assertIn(zip_file_format.format(extension_handler_name, extension_version), os.listdir(conf.get_lib_dir()))
        else:
            self.assertNotIn(zip_file_format.format(extension_handler_name, extension_version), os.listdir(conf.get_lib_dir()))

    def _assert_no_handler_status(self, report_vm_status):
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args  # pylint: disable=unused-variable
        vm_status = args[0]
        self.assertEqual(0, len(vm_status.vmAgent.extensionHandlers))
        return

    @staticmethod
    def _create_mock(test_data, mock_http_get, mock_crypt_util, *_):
        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        mock_crypt_util.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(KNOWN_WIRESERVER_IP)
        protocol.detect()
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
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        # Ensure initial install and enable is successful
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(0, patch_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Next incarnation, update version
        test_data.set_incarnation(2)
        test_data.set_extensions_config_version("1.0.1")
        test_data.set_manifest_version('1.0.1')
        protocol.client.update_goal_state()

        # Ensure the patched command fails
        patch_command.return_value = "exit 1"

        return test_data, exthandlers_handler, protocol

    @staticmethod
    def _create_extension_handlers_handler(protocol):
        handler = get_exthandlers_handler(protocol)
        return handler

    def test_ext_handler(self, *args):
        # Test enable scenario.
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test goal state not changed
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Test goal state changed
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()


        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 1)

        # Test hotfix
        test_data.set_incarnation(3)
        test_data.set_extensions_config_version("1.1.1")
        test_data.set_extensions_config_sequence_number(2)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 2)

        # Test upgrade
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.2.0")
        test_data.set_extensions_config_sequence_number(3)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 3)

        # Test disable
        test_data.set_incarnation(5)
        test_data.set_extensions_config_state(ExtensionRequestedState.Disabled)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.2.0")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_no_handler_status(protocol.report_vm_status)

    def test_it_should_only_download_extension_manifest_once_per_goal_state(self, *args):

        def _assert_handler_status_and_manifest_download_count(protocol, test_data, manifest_count):
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
            self._assert_ext_status(protocol.report_vm_status, "success", 0)
            self.assertEqual(test_data.call_counts['manifest.xml'], manifest_count,
                             "We should have downloaded extension manifest {0} times".format(manifest_count))

        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        _assert_handler_status_and_manifest_download_count(protocol, test_data, 1)

        # Update Incarnation
        test_data.set_incarnation(2)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        _assert_handler_status_and_manifest_download_count(protocol, test_data, 2)

    def test_it_should_fail_handler_on_bad_extension_config_and_report_error(self, mock_get, mock_crypt_util, *args):

        invalid_config_dir = os.path.join(data_dir, "wire", "invalid_config")
        self.assertGreater(len(os.listdir(invalid_config_dir)), 0, "Not even a single bad config file found")

        for bad_config_file_path in os.listdir(invalid_config_dir):
            bad_conf = DATA_FILE.copy()
            bad_conf["ext_conf"] = os.path.join(invalid_config_dir, bad_config_file_path)
            test_data = wire_protocol_data.WireProtocolData(bad_conf)
            exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

            with patch('azurelinuxagent.ga.exthandlers.add_event') as patch_add_event:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0")

                invalid_config_errors = [kw for _, kw in patch_add_event.call_args_list if
                                         kw['op'] == WALAEventOperation.InvalidExtensionConfig]
                self.assertEqual(1, len(invalid_config_errors),
                                 "Error not logged and reported to Kusto for {0}".format(bad_config_file_path))

    def test_it_should_process_valid_extensions_if_present(self, mock_get, mock_crypt_util, *args):

        bad_conf = DATA_FILE.copy()
        bad_conf["ext_conf"] = os.path.join("wire", "ext_conf_invalid_and_valid_handlers.xml")
        test_data = wire_protocol_data.WireProtocolData(bad_conf)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        self.assertTrue(protocol.report_vm_status.called)
        args, _ = protocol.report_vm_status.call_args
        vm_status = args[0]
        expected_handlers = ["OSTCExtensions.InvalidExampleHandlerLinux", "OSTCExtensions.ValidExampleHandlerLinux"]
        self.assertEqual(2, len(vm_status.vmAgent.extensionHandlers))
        for handler in vm_status.vmAgent.extensionHandlers:
            expected_status = "NotReady" if "InvalidExampleHandlerLinux" in handler.name else "Ready"
            expected_ext_count = 0 if "InvalidExampleHandlerLinux" in handler.name else 1
            self.assertEqual(expected_status, handler.status, "Invalid status")
            self.assertIn(handler.name, expected_handlers, "Handler not found")
            self.assertEqual("1.0.0", handler.version, "Incorrect handler version")
            self.assertEqual(expected_ext_count, len([ext for ext in vm_status.vmAgent.extensionHandlers if
                                                      ext.name == handler.name and ext.extension_status is not None]),
                             "Incorrect extensions enabled")
            expected_handlers.remove(handler.name)
        self.assertEqual(0, len(expected_handlers), "All handlers not reported status")


    def test_it_should_ignore_case_when_parsing_plugin_settings(self, mock_get, mock_crypt_util, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_CASE_MISMATCH_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        expected_ext_handlers = ["OSTCExtensions.ExampleHandlerLinux", "Microsoft.Powershell.ExampleExtension",
                                 "Microsoft.EnterpriseCloud.Monitoring.ExampleHandlerLinux",
                                 "Microsoft.CPlat.Core.ExampleExtensionLinux",
                                 "Microsoft.OSTCExtensions.Edp.ExampleExtensionLinuxInTest"]

        self.assertTrue(protocol.report_vm_status.called, "Handler status not reported")
        args, _ = protocol.report_vm_status.call_args
        vm_status = args[0]
        self.assertEqual(len(expected_ext_handlers), len(vm_status.vmAgent.extensionHandlers),
                         "No of Extension handlers dont match")

        for handler_status in vm_status.vmAgent.extensionHandlers:
            self.assertEqual("Ready", handler_status.status, "Handler is not Ready")
            self.assertIn(handler_status.name, expected_ext_handlers, "Handler not reported")
            self.assertEqual("1.0.0", handler_status.version, "Handler version not matching")
            self.assertEqual(1, len(
                [status for status in vm_status.vmAgent.extensionHandlers if status.name == handler_status.name]),
                             "No settings were found for this extension")
            expected_ext_handlers.remove(handler_status.name)

        self.assertEqual(0, len(expected_ext_handlers), "All handlers not reported")

    def test_ext_handler_no_settings(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_NO_SETTINGS)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        test_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        with enable_invocations(test_ext) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0.0")
            invocation_record.compare(
                (test_ext, ExtensionCommandNames.INSTALL),
                (test_ext, ExtensionCommandNames.ENABLE)
            )

        # Uninstall the Plugin and make sure Disable called
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
        protocol.client.update_goal_state()

        with enable_invocations(test_ext) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self.assertTrue(protocol.report_vm_status.called)
            args, _ = protocol.report_vm_status.call_args
            self.assertEqual(0, len(args[0].vmAgent.extensionHandlers))
            invocation_record.compare(
                (test_ext, ExtensionCommandNames.DISABLE),
                (test_ext, ExtensionCommandNames.UNINSTALL)
            )

    def test_ext_handler_no_public_settings(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_NO_PUBLIC)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

    def test_ext_handler_no_ext(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        # Assert no extension handler status
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        self._assert_no_handler_status(protocol.report_vm_status)

    def test_ext_handler_sequencing(self, *args):
        # Test enable scenario.
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        dep_ext_level_2 = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        dep_ext_level_1 = extension_emulator(name="OSTCExtensions.OtherExampleHandlerLinux")

        with enable_invocations(dep_ext_level_2, dep_ext_level_1) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                        expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
            self._assert_ext_status(protocol.report_vm_status, "success", 0,
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

            # check handler list and dependency levels
            self.assertTrue(exthandlers_handler.ext_handlers is not None)
            self.assertTrue(exthandlers_handler.ext_handlers is not None)
            self.assertEqual(len(exthandlers_handler.ext_handlers), 2)
            self.assertEqual(1, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_1.name).settings[0].dependencyLevel)
            self.assertEqual(2, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_2.name).settings[0].dependencyLevel)

            # Ensure the invocation order follows the dependency levels
            invocation_record.compare(
                (dep_ext_level_1, ExtensionCommandNames.INSTALL),
                (dep_ext_level_1, ExtensionCommandNames.ENABLE),
                (dep_ext_level_2, ExtensionCommandNames.INSTALL),
                (dep_ext_level_2, ExtensionCommandNames.ENABLE)
            )

        # Test goal state not changed
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        # Test goal state changed
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        # Swap the dependency ordering
        dep_ext_level_3 = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        dep_ext_level_4 = extension_emulator(name="OSTCExtensions.OtherExampleHandlerLinux")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"", "dependencyLevel=\"3\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"", "dependencyLevel=\"4\"")
        protocol.client.update_goal_state()

        with enable_invocations(dep_ext_level_3, dep_ext_level_4) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
            self._assert_ext_status(protocol.report_vm_status, "success", 1)

            self.assertEqual(len(exthandlers_handler.ext_handlers), 2)
            self.assertEqual(3, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_3.name).settings[0].dependencyLevel)
            self.assertEqual(4, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_4.name).settings[0].dependencyLevel)

            # Ensure the invocation order follows the dependency levels
            invocation_record.compare(
                (dep_ext_level_3, ExtensionCommandNames.ENABLE),
                (dep_ext_level_4, ExtensionCommandNames.ENABLE)
            )

        # Test disable
        # In the case of disable, the last extension to be enabled should be
        # the first extension disabled. The first extension enabled should be
        # the last one disabled.
        test_data.set_incarnation(3)
        test_data.set_extensions_config_state(ExtensionRequestedState.Disabled)
        protocol.client.update_goal_state()

        with enable_invocations(dep_ext_level_3, dep_ext_level_4) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        self.assertEqual(3, next(handler for handler in exthandlers_handler.ext_handlers if
                                 handler.name == dep_ext_level_3.name).settings[0].dependencyLevel)
        self.assertEqual(4, next(handler for handler in exthandlers_handler.ext_handlers if
                                 handler.name == dep_ext_level_4.name).settings[0].dependencyLevel)

        # Ensure the invocation order follows the dependency levels
        invocation_record.compare(
            (dep_ext_level_4, ExtensionCommandNames.DISABLE),
            (dep_ext_level_3, ExtensionCommandNames.DISABLE)
        )

        # Test uninstall
        # In the case of uninstall, the last extension to be installed should be
        # the first extension uninstalled. The first extension installed
        # should be the last one uninstalled.
        test_data.set_incarnation(4)
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)

        # Swap the dependency ordering AGAIN
        dep_ext_level_5 = extension_emulator(name="OSTCExtensions.OtherExampleHandlerLinux")
        dep_ext_level_6 = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"3\"", "dependencyLevel=\"6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"4\"", "dependencyLevel=\"5\"")
        protocol.client.update_goal_state()

        with enable_invocations(dep_ext_level_5, dep_ext_level_6) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self._assert_no_handler_status(protocol.report_vm_status)
            self.assertEqual(len(exthandlers_handler.ext_handlers), 2)
            self.assertEqual(5, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_5.name).settings[0].dependencyLevel)
            self.assertEqual(6, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_6.name).settings[0].dependencyLevel)

            # Ensure the invocation order follows the dependency levels
            invocation_record.compare(
                (dep_ext_level_6, ExtensionCommandNames.UNINSTALL),
                (dep_ext_level_5, ExtensionCommandNames.UNINSTALL)
            )

    def test_it_should_process_sequencing_properly_even_if_no_settings_for_dependent_extension(
            self, mock_get, mock_crypt, *args):
        test_data_file = DATA_FILE.copy()
        test_data_file["ext_conf"] = "wire/ext_conf_dependencies_with_empty_settings.xml"
        test_data = wire_protocol_data.WireProtocolData(test_data_file)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt, *args)

        ext_1 = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        ext_2 = extension_emulator(name="OSTCExtensions.OtherExampleHandlerLinux")

        with enable_invocations(ext_1, ext_2) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # Ensure no extension status was reported for OtherExampleHandlerLinux as no settings provided for it
            self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0.0",
                                        expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

            # Ensure correct status reported back for the other extension with settings
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                        expected_handler_name="OSTCExtensions.ExampleHandlerLinux")
            self._assert_ext_status(protocol.report_vm_status, "success", 0,
                                    expected_handler_name="OSTCExtensions.ExampleHandlerLinux")

            # Ensure the invocation order follows the dependency levels
            invocation_record.compare(
                (ext_2, ExtensionCommandNames.INSTALL),
                (ext_2, ExtensionCommandNames.ENABLE),
                (ext_1, ExtensionCommandNames.INSTALL),
                (ext_1, ExtensionCommandNames.ENABLE)
            )

    def test_ext_handler_sequencing_should_fail_if_handler_failed(self, mock_get, mock_crypt, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt, *args)

        original_popen = subprocess.Popen

        def _assert_event_reported_only_on_incarnation_change(expected_count=1):
            handler_seq_reporting = [kwargs for _, kwargs in patch_add_event.call_args_list if kwargs[
                'op'] == WALAEventOperation.ExtensionProcessing and "Skipping processing of extensions since execution of dependent extension" in
                                     kwargs['message']]
            self.assertEqual(len(handler_seq_reporting), expected_count,
                             "Error should be reported only on incarnation change")

        def mock_fail_extension_commands(args, **kwargs):
            if 'sample.py' in args:
                return original_popen("fail_this_command", **kwargs)
            return original_popen(args, **kwargs)

        with patch("subprocess.Popen", mock_fail_extension_commands):
            with patch('azurelinuxagent.ga.exthandlers.add_event') as patch_add_event:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0",
                                            expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

                _assert_event_reported_only_on_incarnation_change(expected_count=1)

                test_data.set_incarnation(2)
                protocol.client.update_goal_state()

                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                # We should report error again on incarnation change
                _assert_event_reported_only_on_incarnation_change(expected_count=2)

        # Test it recovers on a new goal state if Handler succeeds
        test_data.set_incarnation(3)
        test_data.set_extensions_config_sequence_number(1)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
        self._assert_ext_status(protocol.report_vm_status, "success", 1,
                                expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        # Update incarnation to confirm extension invocation order
        test_data.set_incarnation(4)
        protocol.client.update_goal_state()

        dep_ext_level_2 = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux")
        dep_ext_level_1 = extension_emulator(name="OSTCExtensions.OtherExampleHandlerLinux")

        with enable_invocations(dep_ext_level_2, dep_ext_level_1) as invocation_record:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # check handler list and dependency levels
            self.assertTrue(exthandlers_handler.ext_handlers is not None)
            self.assertTrue(exthandlers_handler.ext_handlers is not None)
            self.assertEqual(len(exthandlers_handler.ext_handlers), 2)
            self.assertEqual(1, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_1.name).settings[0].dependencyLevel)
            self.assertEqual(2, next(handler for handler in exthandlers_handler.ext_handlers if
                                     handler.name == dep_ext_level_2.name).settings[0].dependencyLevel)

            # Ensure the invocation order follows the dependency levels
            invocation_record.compare(
                (dep_ext_level_1, ExtensionCommandNames.ENABLE),
                (dep_ext_level_2, ExtensionCommandNames.ENABLE)
            )

    def test_ext_handler_sequencing_default_dependency_level(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(exthandlers_handler.ext_handlers[0].settings[0].dependencyLevel, 0)
        self.assertEqual(exthandlers_handler.ext_handlers[0].settings[0].dependencyLevel, 0)

    def test_ext_handler_sequencing_invalid_dependency_level(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING)
        test_data.set_incarnation(2)
        test_data.set_extensions_config_sequence_number(1)
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"1\"",
                                                        "dependencyLevel=\"a6\"")
        test_data.ext_conf = test_data.ext_conf.replace("dependencyLevel=\"2\"",
                                                        "dependencyLevel=\"5b\"")
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(exthandlers_handler.ext_handlers[0].settings[0].dependencyLevel, 0)
        self.assertEqual(exthandlers_handler.ext_handlers[0].settings[0].dependencyLevel, 0)

    def test_ext_handler_rollingupgrade(self, *args):
        # Test enable scenario.
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_ROLLINGUPGRADE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test goal state changed
        test_data.set_incarnation(2)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test minor version bump
        test_data.set_incarnation(3)
        test_data.set_extensions_config_version("1.1.0")
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test hotfix version bump
        test_data.set_incarnation(4)
        test_data.set_extensions_config_version("1.1.1")
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test disable
        test_data.set_incarnation(5)
        test_data.set_extensions_config_state(ExtensionRequestedState.Disabled)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "NotReady", 1, "1.1.1")

        # Test uninstall
        test_data.set_incarnation(6)
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test uninstall again!
        test_data.set_incarnation(7)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_no_handler_status(protocol.report_vm_status)

        # Test re-install
        test_data.set_incarnation(8)
        test_data.set_extensions_config_state(ExtensionRequestedState.Enabled)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test version bump post-re-install
        test_data.set_incarnation(9)
        test_data.set_extensions_config_version("1.2.0")
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.2.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Test rollback
        test_data.set_incarnation(10)
        test_data.set_extensions_config_version("1.1.0")
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.1.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

    def test_it_should_create_extension_events_dir_and_set_handler_environment_only_if_extension_telemetry_enabled(self, *args):

        for enable_extensions in [False, True]:
            tmp_lib_dir = tempfile.mkdtemp(prefix="ExtensionEnabled{0}".format(enable_extensions))
            with patch("azurelinuxagent.common.conf.get_lib_dir", return_value=tmp_lib_dir):
                with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", enable_extensions):
                    # Create new object for each run to force re-installation of extensions as we
                    # only create handler_environment on installation
                    test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_MULTIPLE_EXT)
                    exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()

                    self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
                    self._assert_ext_status(protocol.report_vm_status, "success", 0)

                    for ext_handler in exthandlers_handler.ext_handlers:
                        ehi = ExtHandlerInstance(ext_handler, protocol)
                        self.assertEqual(enable_extensions, os.path.exists(ehi.get_extension_events_dir()),
                                         "Events directory incorrectly set")
                        handler_env_json = ehi.get_env_file()
                        with open(handler_env_json, 'r') as env_json:
                            env_data = json.load(env_json)

                        self.assertEqual(enable_extensions, HandlerEnvironment.eventsFolder in env_data[0][
                            HandlerEnvironment.handlerEnvironment],
                                         "eventsFolder wrongfully set in HandlerEnvironment.json file")

                        if enable_extensions:
                            self.assertEqual(ehi.get_extension_events_dir(),
                                             env_data[0][HandlerEnvironment.handlerEnvironment][
                                                 HandlerEnvironment.eventsFolder], "Events directory dont match")

            # Clean the File System for the next test run
            if os.path.exists(tmp_lib_dir):
                shutil.rmtree(tmp_lib_dir, ignore_errors=True)

    def test_it_should_not_delete_extension_events_directory_on_extension_uninstall(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
            self._assert_ext_status(protocol.report_vm_status, "success", 0)

            ehi = ExtHandlerInstance(exthandlers_handler.ext_handlers[0], protocol)
            self.assertTrue(os.path.exists(ehi.get_extension_events_dir()), "Events directory should exist")

            # Uninstall extensions now
            test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
            test_data.set_incarnation(2)
            protocol.client.update_goal_state()

            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertTrue(os.path.exists(ehi.get_extension_events_dir()), "Events directory should still exist")

    def test_it_should_uninstall_unregistered_extensions_properly(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Update version and set it to uninstall. That is how it would be propagated by CRP if a version 1.0.0 is
        # unregistered in PIR and a new version 1.0.1 is published.
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
        test_data.set_extensions_config_version("1.0.1")
        # Since the installed version is not in PIR anymore, we need to also remove it from manifest file
        test_data.manifest = test_data.manifest.replace("1.0.0", "9.9.9")
        test_data.set_incarnation(2)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        args, _ = protocol.report_vm_status.call_args
        vm_status = args[0]
        self.assertEqual(0, len(vm_status.vmAgent.extensionHandlers),
                         "The extension should not be reported as it is uninstalled")

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_report_status_permanent(self, mock_add_event, mock_error_state, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        protocol.report_vm_status = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        args, kw = mock_add_event.call_args
        self.assertEqual(False, kw['is_success'])
        self.assertTrue("Failed to report vm agent status" in kw['message'])
        self.assertEqual("ReportStatusExtended", kw['op'])

    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_report_status_resource_gone(self, mock_add_event, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        protocol.report_vm_status = Mock(side_effect=ResourceGoneError)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        args, kw = mock_add_event.call_args
        self.assertEqual(False, kw['is_success'])
        self.assertTrue("ResourceGoneError" in kw['message'])
        self.assertEqual("ReportStatus", kw['op'])

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered')
    @patch('azurelinuxagent.ga.exthandlers.add_event')
    def test_ext_handler_download_failure_permanent_ProtocolError(self, mock_add_event, mock_error_state, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        protocol.get_goal_state().fetch_extension_manifest = Mock(side_effect=ProtocolError)

        mock_error_state.return_value = True

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        event_occurrences = [kw for _, kw in mock_add_event.call_args_list if
                             "[ExtensionError] Failed to get ext handler pkgs" in kw['message']]
        self.assertEqual(1, len(event_occurrences))
        self.assertFalse(event_occurrences[0]['is_success'])
        self.assertTrue("Failed to get ext handler pkgs" in event_occurrences[0]['message'])
        self.assertTrue("ProtocolError" in event_occurrences[0]['message'])

    @patch('azurelinuxagent.ga.exthandlers.fileutil')
    def test_ext_handler_io_error(self, mock_fileutil, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter

        mock_fileutil.write_file.return_value = IOError("Mock IO Error")

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

    def _assert_ext_status(self, vm_agent_status, expected_status,
                           expected_seq_no, expected_handler_name="OSTCExtensions.ExampleHandlerLinux", expected_msg=None):

        self.assertTrue(vm_agent_status.called)
        args, _ = vm_agent_status.call_args
        vm_status = args[0]
        ext_status = next(handler_status.extension_status for handler_status in vm_status.vmAgent.extensionHandlers if
                          handler_status.name == expected_handler_name)
        self.assertEqual(expected_status, ext_status.status)
        self.assertEqual(expected_seq_no, ext_status.sequenceNumber)

        if expected_msg is not None:
            self.assertIn(expected_msg, ext_status.message)

    def test_it_should_initialise_and_use_command_execution_log_for_extensions(self, mock_get, mock_crypt_util, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        command_execution_log = os.path.join(conf.get_ext_log_dir(), "OSTCExtensions.ExampleHandlerLinux",
                                             "CommandExecution.log")
        self.assertTrue(os.path.exists(command_execution_log), "CommandExecution.log file not found")
        self.assertGreater(os.path.getsize(command_execution_log), 0, "The file should not be empty")

    def test_ext_handler_no_reporting_status(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

        # Remove status file and re-run collecting extension status
        status_file = os.path.join(self.tmp_dir,
                                   "OSTCExtensions.ExampleHandlerLinux-1.0.0",
                                   "status", "0.status")
        self.assertTrue(os.path.isfile(status_file))
        os.remove(status_file)

        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.transitioning, 0,
                                expected_msg="This status is being reported by the Guest Agent since no status "
                                             "file was reported by extension OSTCExtensions.ExampleHandlerLinux")

    def test_wait_for_handler_completion_no_status(self, mock_http_get, mock_crypt_util, *args):
        """
        Testing depends-on scenario when there is no status file reported by the extension.
        Expected to retry and eventually report failure for all dependent extensions.
        """
        exthandlers_handler, protocol = self._create_mock(
            wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING), mock_http_get, mock_crypt_util, *args)

        original_popen = subprocess.Popen

        def mock_popen(cmd, *args, **kwargs):
            # For the purpose of this test, deleting the placeholder status file created by the agent
            if "sample.py" in cmd:
                status_path = os.path.join(kwargs['env'][ExtCommandEnvVariable.ExtensionPath], "status",
                                           "{0}.status".format(kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber]))
                mock_popen.deleted_status_file = status_path
                if os.path.exists(status_path):
                    os.remove(status_path)
            return original_popen(["echo", "Yes"], *args, **kwargs)

        with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            with patch('azurelinuxagent.ga.exthandlers._DEFAULT_EXT_TIMEOUT_MINUTES', 0.01):
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                # The Handler Status for the base extension should be ready as it was executed successfully by the agent
                self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                            expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")
                # The extension status reported by the Handler should be transitioning since no status file was found
                self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.transitioning, 0,
                                        expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux",
                                        expected_msg="This status is being reported by the Guest Agent since no status "
                                                     "file was reported by extension OSTCExtensions.OtherExampleHandlerLinux")

                # The Handler Status for the dependent extension should be NotReady as it was not executed at all
                # And since it was not executed, it should not report any extension status either
                self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0",
                                            expected_msg="Dependent Extension OSTCExtensions.OtherExampleHandlerLinux did not reach a terminal state within the allowed timeout. Last status was {0}".format(
                                                ExtensionStatusValue.warning))

    def test_it_should_not_create_placeholder_for_single_config_extensions(self, mock_http_get, mock_crypt_util, *args):
        original_popen = subprocess.Popen

        def mock_popen(cmd, *_, **kwargs):
            if 'env' in kwargs:
                if ExtensionCommandNames.ENABLE not in cmd:
                    # To force the test extension to not create a status file on Install, changing command
                    return original_popen(["echo", "not-enable"], *_, **kwargs)

                seq_no = kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber]
                ext_path = kwargs['env'][ExtCommandEnvVariable.ExtensionPath]
                status_file_name = "{0}.status".format(seq_no)
                status_file = os.path.join(ext_path, "status", status_file_name)
                self.assertFalse(os.path.exists(status_file), "Placeholder file should not be created for single config extensions")

            return original_popen(cmd, *_, **kwargs)

        aks_test_mock = DATA_FILE.copy()
        aks_test_mock["ext_conf"] = "wire/ext_conf_aks_extension.xml"

        exthandlers_handler, protocol = self._create_mock(wire_protocol_data.WireProtocolData(aks_test_mock),
                                                          mock_http_get, mock_crypt_util, *args)

        with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                        expected_handler_name="OSTCExtensions.ExampleHandlerLinux")
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                        expected_handler_name="Microsoft.AKS.Compute.AKS.Linux.AKSNode")
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                        expected_handler_name="Microsoft.AKS.Compute.AKS-Engine.Linux.Billing")
            # Extension without settings
            self._assert_handler_status(protocol.report_vm_status, "Ready", 0, "1.0.0",
                                        expected_handler_name="Microsoft.AKS.Compute.AKS.Linux.Billing")

            self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.success, 0,
                                    expected_handler_name="OSTCExtensions.ExampleHandlerLinux",
                                    expected_msg="Enabling non-AKS")
            self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.success, 0,
                                    expected_handler_name="Microsoft.AKS.Compute.AKS.Linux.AKSNode",
                                    expected_msg="Enabling AKSNode")
            self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.success, 0,
                                    expected_handler_name="Microsoft.AKS.Compute.AKS-Engine.Linux.Billing",
                                    expected_msg="Enabling AKSBilling")

    def test_it_should_include_part_of_status_in_ext_handler_message(self, mock_http_get, mock_crypt_util, *args):
        """
        Testing scenario when the status file is invalid,
        The extension status reported by the Handler should contain a fragment of status file for
        debugging.
        """
        exthandlers_handler, protocol = self._create_mock(
            wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE), mock_http_get, mock_crypt_util, *args)

        original_popen = subprocess.Popen

        def mock_popen(cmd, *args, **kwargs):
            # For the purpose of this test, replacing the status file with file that could not be parsed
            if "sample.py" in cmd:
                status_path = os.path.join(kwargs['env'][ExtCommandEnvVariable.ExtensionPath], "status",
                                           "{0}.status".format(kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber]))
                invalid_json_path = os.path.join(data_dir, "ext", "sample-status-invalid-json-format.json")

                if 'enable' in cmd:
                    invalid_json = fileutil.read_file(invalid_json_path)
                    fileutil.write_file(status_path,invalid_json)

            return original_popen(["echo", "Yes"], *args, **kwargs)

        with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # The Handler Status for the base extension should be ready as it was executed successfully by the agent
            self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                            expected_handler_name="OSTCExtensions.ExampleHandlerLinux")
            # The extension status reported by the Handler should contain a fragment of status file for
            # debugging. The uniqueMachineId tag comes from status file
            self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.error, 0,
                                    expected_handler_name="OSTCExtensions.ExampleHandlerLinux",
                                    expected_msg="\"uniqueMachineId\": \"e5e5602b-48a6-4c35-9f96-752043777af1\"")

    def test_wait_for_handler_completion_success_status(self, mock_http_get, mock_crypt_util, *args):
        """
        Testing depends-on scenario on a successful case. Expected to report the status for both extensions properly.
        """
        exthandlers_handler, protocol = self._create_mock(
            wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING), mock_http_get, mock_crypt_util, *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0",
                                    expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux",
                                    expected_msg='Plugin enabled')
        # The extension status reported by the Handler should be an error since no status file was found
        self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.success, 0,
                                expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

        # The Handler Status for the dependent extension should be NotReady as it was not executed at all
        # And since it was not executed, it should not report any extension status either
        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0", expected_msg='Plugin enabled')
        self._assert_ext_status(protocol.report_vm_status, ExtensionStatusValue.success, 0)

    def test_wait_for_handler_completion_error_status(self, mock_http_get, mock_crypt_util, *args):
        """
        Testing wait_for_handler_completion() when there is error status.
        Expected to return False.
        """
        exthandlers_handler, protocol = self._create_mock(
            wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SEQUENCING), mock_http_get, mock_crypt_util, *args)

        original_popen = subprocess.Popen

        def mock_popen(cmd, *args, **kwargs):
            # For the purpose of this test, deleting the placeholder status file created by the agent
            if "sample.py" in cmd:
                return original_popen(["/fail/this/command"], *args, **kwargs)
            return original_popen(cmd, *args, **kwargs)

        with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # The Handler Status for the base extension should be NotReady as it failed
            self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0",
                                        expected_handler_name="OSTCExtensions.OtherExampleHandlerLinux")

            # The Handler Status for the dependent extension should be NotReady as it was not executed at all
            # And since it was not executed, it should not report any extension status either
            self._assert_handler_status(protocol.report_vm_status, "NotReady", 0, "1.0.0",
                                        expected_msg='Skipping processing of extensions since execution of dependent extension OSTCExtensions.OtherExampleHandlerLinux failed')

    def test_get_ext_handling_status(self, *args):
        """
        Testing get_ext_handling_status() function with various cases and
        verifying against the expected values
        """
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter

        handler_name = "Handler"
        exthandler = Extension(name=handler_name)
        extension = ExtensionSettings(name=handler_name)
        exthandler.settings.append(extension)

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
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter

        handler_name = "Handler"
        exthandler = Extension(name=handler_name)
        extension = ExtensionSettings(name=handler_name)
        exthandler.settings.append(extension)

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
                        datafile = wire_protocol_data.DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION
                    else:
                        datafile = wire_protocol_data.DATA_FILE_EXT_INTERNALVERSION
                else:
                    config_version = '1.0.0'
                    decision_version = '1.0.0'
                    if autoupgrade:
                        datafile = wire_protocol_data.DATA_FILE_EXT_AUTOUPGRADE
                    else:
                        datafile = wire_protocol_data.DATA_FILE

                _, protocol = self._create_mock(wire_protocol_data.WireProtocolData(datafile), *args)  # pylint: disable=no-value-for-parameter
                ext_handlers = protocol.get_goal_state().extensions_goal_state.extensions
                self.assertEqual(1, len(ext_handlers))
                ext_handler = ext_handlers[0]
                self.assertEqual('OSTCExtensions.ExampleHandlerLinux', ext_handler.name)
                self.assertEqual(config_version, ext_handler.version, "config version.")
                ExtHandlerInstance(ext_handler, protocol).decide_version()
                self.assertEqual(decision_version, ext_handler.version, "decision version.")

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

        _, protocol = self._create_mock(wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE), *args)  # pylint: disable=no-value-for-parameter
        version_uri = 'http://mock-goal-state/Microsoft.OSTCExtensions_ExampleHandlerLinux_asiaeast_manifest.xml'

        for (installed_version, config_version, expected_version) in cases:
            ext_handler = Mock()
            ext_handler.properties = Mock()
            ext_handler.name = 'OSTCExtensions.ExampleHandlerLinux'
            ext_handler.manifest_uris = [version_uri]
            ext_handler.version = config_version

            ext_handler_instance = ExtHandlerInstance(ext_handler, protocol)
            ext_handler_instance.get_installed_version = Mock(return_value=installed_version)

            ext_handler_instance.decide_version()
            self.assertEqual(expected_version, ext_handler.version)

    @patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False)
    def test_extensions_disabled(self, _, *args):
        # test status is reported for no extensions
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_NO_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_no_handler_status(protocol.report_vm_status)

        # test status is reported, but extensions are not processed
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        report_vm_status = protocol.report_vm_status
        self.assertTrue(report_vm_status.called)
        args, kw = report_vm_status.call_args  # pylint: disable=unused-variable
        vm_status = args[0]
        self.assertEqual(1, len(vm_status.vmAgent.extensionHandlers))
        exthandler = vm_status.vmAgent.extensionHandlers[0]
        self.assertEqual(-1, exthandler.code)
        self.assertEqual('NotReady', exthandler.status)
        self.assertEqual("Extension will not be processed since extension processing is disabled. To enable extension processing, set Extensions.Enabled=y in '/etc/waagent.conf'", exthandler.message)
        ext_status = exthandler.extension_status
        self.assertEqual(-1, ext_status.code)
        self.assertEqual('error', ext_status.status)
        self.assertEqual("Extension will not be processed since extension processing is disabled. To enable extension processing, set Extensions.Enabled=y in '/etc/waagent.conf'", ext_status.message)

    def test_extensions_deleted(self, *args):
        # Ensure initial enable is successful
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_DELETION)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Update incarnation, simulate new extension version and old one deleted
        test_data.set_incarnation(2)
        test_data.set_extensions_config_version("1.0.1")
        test_data.set_manifest_version('1.0.1')
        protocol.client.update_goal_state()

        # Ensure new extension can be enabled
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.install', side_effect=ExtHandlerInstance.install,
           autospec=True)
    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_install_command')
    def test_install_failure(self, patch_get_install_command, patch_install, *args):
        """
        When extension install fails, the operation should not be retried.
        """
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        # Ensure initial install is unsuccessful
        patch_get_install_command.return_value = "exit.sh 1"

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_install.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_install_command')
    def test_install_failure_check_exception_handling(self, patch_get_install_command, *args):
        """
        When extension install fails, the operation should be reported to our telemetry service.
        """
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        # Ensure install is unsuccessful
        patch_get_install_command.return_value = "exit.sh 1"
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, expected_status="NotReady", expected_ext_count=0,
                                    version="1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command')
    def test_enable_failure_check_exception_handling(self, patch_get_enable_command, *args):
        """
        When extension enable fails, the operation should be reported.
        """
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        # Ensure initial install is successful, but enable fails
        patch_get_enable_command.call_count = 0
        patch_get_enable_command.return_value = "exit.sh 1"
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_get_enable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_disable_failure_with_exception_handling(self, patch_get_disable_command,
                                                     *args):
        """
        When extension disable fails, the operation should be reported.
        """
        # Ensure initial install and enable is successful, but disable fails
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        patch_get_disable_command.call_count = 0
        patch_get_disable_command.return_value = "exit 1"

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(0, patch_get_disable_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Next incarnation, disable extension
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state(ExtensionRequestedState.Disabled)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_get_disable_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.0")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_uninstall_failure(self, patch_get_uninstall_command, *args):
        """
        When extension uninstall fails, the operation should not be retried.
        """
        # Ensure initial install and enable is successful, but uninstall fails
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter
        patch_get_uninstall_command.call_count = 0
        patch_get_uninstall_command.return_value = "exit 1"

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(0, patch_get_uninstall_command.call_count)
        self.assertEqual(1, protocol.report_vm_status.call_count)
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

        # Next incarnation, disable extension
        test_data.set_incarnation(2)
        test_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
        protocol.client.update_goal_state()

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_get_uninstall_command.call_count)
        self.assertEqual(2, protocol.report_vm_status.call_count)
        self.assertEqual("Ready", protocol.report_vm_status.call_args[0][0].vmAgent.status)
        self._assert_no_handler_status(protocol.report_vm_status)

        # Ensure there are no further retries
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_get_uninstall_command.call_count)
        self.assertEqual(3, protocol.report_vm_status.call_count)
        self.assertEqual("Ready", protocol.report_vm_status.call_args[0][0].vmAgent.status)
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
        extension_name = exthandlers_handler.ext_handlers[0].name
        extension_calls = []
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Maintain an internal list of invoked commands of the test extension to assert on later
            if extension_name in args[0]:
                extension_calls.append(args[0])
            return original_popen(*args, **kwargs)

        with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            update_command_count = len([extension_call for extension_call in extension_calls
                                        if patch_get_update_command.return_value in extension_call])
            enable_command_count = len([extension_call for extension_call in extension_calls
                                        if "-enable" in extension_call])

            self.assertEqual(1, update_command_count)
            self.assertEqual(0, enable_command_count)

            # We report the failure of the new extension version
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

            # If the incarnation number changes (there's a new goal state), ensure we go through the entire upgrade
            # process again.
            test_data.set_incarnation(3)
            protocol.client.update_goal_state()

            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            update_command_count = len([extension_call for extension_call in extension_calls
                                        if patch_get_update_command.return_value in extension_call])
            enable_command_count = len([extension_call for extension_call in extension_calls
                                        if "-enable" in extension_call])
            self.assertEqual(2, update_command_count)
            self.assertEqual(0, enable_command_count)

            # We report the failure of the new extension version
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_failure_when_prev_version_disable_fails(self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command, *args)  # pylint: disable=unused-variable

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # When the previous version's disable fails, we expect the upgrade scenario to fail, so the enable
            # for the new version is not called and the new version handler's status is reported as not ready.
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_failure_when_prev_version_disable_fails_and_recovers_on_next_incarnation(self, patch_get_disable_command,
                                                                                                         *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # When the previous version's disable fails, we expect the upgrade scenario to fail, so the enable
            # for the new version is not called and the new version handler's status is reported as not ready.
            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(0, patch_get_enable_command.call_count)
            self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

            # Force a new goal state incarnation, only then will we attempt the upgrade again
            test_data.set_incarnation(3)
            protocol.client.update_goal_state()

            # Ensure disable won't fail by making launch_command a no-op
            with patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.launch_command') as patch_launch_command:  # pylint: disable=unused-variable
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                self.assertEqual(2, patch_get_disable_command.call_count)
                self.assertEqual(1, patch_get_enable_command.call_count)
                self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_failure_when_prev_version_disable_fails_incorrect_zip(self, patch_get_disable_command,
                                                                                      *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,  # pylint: disable=unused-variable
                                                                                          *args)

        # The download logic has retry logic that sleeps before each try - make sleep a no-op.
        with patch("time.sleep"):
            with patch("zipfile.ZipFile.extractall") as patch_zipfile_extractall:
                with patch(
                        'azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command') as patch_get_enable_command:
                    patch_zipfile_extractall.side_effect = raise_ioerror
                    # The zipfile was corrupt and the upgrade sequence failed
                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()


                    # We never called the disable of the old version due to the failure when unzipping the new version,
                    # nor the enable of the new version
                    self.assertEqual(0, patch_get_disable_command.call_count)
                    self.assertEqual(0, patch_get_enable_command.call_count)

                    # Ensure we are processing the same goal state only once
                    loop_run = 5
                    for x in range(loop_run):  # pylint: disable=unused-variable
                        exthandlers_handler.run()
                        exthandlers_handler.report_ext_handlers_status()

                    self.assertEqual(0, patch_get_disable_command.call_count)
                    self.assertEqual(0, patch_get_enable_command.call_count)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_old_handler_reports_failure_on_disable_fail_on_update(self, patch_get_disable_command, *args):
        old_version, new_version = "1.0.0", "1.0.1"
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch.object(ExtHandlerInstance, "report_event", autospec=True) as patch_report_event:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(1, patch_get_disable_command.call_count)

            old_version_args, old_version_kwargs = patch_report_event.call_args
            new_version_args, new_version_kwargs = patch_report_event.call_args_list[0]

            self.assertEqual(new_version_args[0].ext_handler.version, new_version,
                             "The first call to report event should be from the new version of the ext-handler "
                             "to report download succeeded")

            self.assertEqual(new_version_kwargs['message'], "Download succeeded",
                             "The message should be Download Succedded")

            self.assertEqual(old_version_args[0].ext_handler.version, old_version,
                             "The last report event call should be from the old version ext-handler "
                             "to report the event from the previous version")

            self.assertFalse(old_version_kwargs['is_success'], "The last call to report event should be for a failure")

            self.assertTrue('Error' in old_version_kwargs['message'], "No error reported")

            # This is ensuring that the error status is being written to the new version
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version=new_version)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_update_command')
    def test_upgrade_failure_with_exception_handling(self, patch_get_update_command, *args):
        """
        Extension upgrade failure should not be retried
        """
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_update_command,  # pylint: disable=unused-variable
                                                                                          *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self.assertEqual(1, patch_get_update_command.call_count)
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=1, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_pass_when_continue_on_update_failure_is_true_and_prev_version_disable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "This should be called twice, for both disable and uninstall")

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_extension_upgrade_should_pass_when_continue_on_update_failue_is_true_and_prev_version_uninstall_fails(
            self, patch_get_uninstall_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_uninstall_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(1, patch_get_uninstall_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "This should be called twice, for both disable and uninstall")

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_false_and_prev_version_disable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=False) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(1, patch_get_disable_command.call_count)
            self.assertEqual(1, mock_continue_on_update_failure.call_count,
                             "The first call would raise an exception")

        # Assert test scenario
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_uninstall_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_false_and_prev_version_uninstall_fails(
            self, patch_get_uninstall_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_uninstall_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=False) \
                as mock_continue_on_update_failure:
            # These are just testing the mocks have been called and asserting the test conditions have been met
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            self.assertEqual(1, patch_get_uninstall_command.call_count)
            self.assertEqual(2, mock_continue_on_update_failure.call_count,
                             "The second call would raise an exception")

        # Assert test scenario
        self._assert_handler_status(protocol.report_vm_status, "NotReady", expected_ext_count=0, version="1.0.1")

    @patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_disable_command')
    def test_extension_upgrade_should_fail_when_continue_on_update_failure_is_true_and_old_disable_and_new_enable_fails(
            self, patch_get_disable_command, *args):
        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(patch_get_disable_command,  # pylint: disable=unused-variable
                                                                                          *args)

        with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.is_continue_on_update_failure', return_value=True) \
                as mock_continue_on_update_failure:
            with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.get_enable_command', return_value="exit 1")\
                    as patch_get_enable:
                # These are just testing the mocks have been called and asserting the test conditions have been met
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

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
            exthandlers_handler.report_ext_handlers_status()

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
            protocol.client.update_goal_state()

            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            _, new_enable_kwargs = patch_start_cmd.call_args

            # Ensure the new run didn't have Disable Return Code env variable
            self.assertNotIn(ExtCommandEnvVariable.DisableReturnCode, new_enable_kwargs['env'])

            # Ensure the new run had Uninstall Return Code env variable == NOT_RUN
            self.assertIn(ExtCommandEnvVariable.UninstallReturnCode, new_enable_kwargs['env'])
            self.assertTrue(
                new_enable_kwargs['env'][ExtCommandEnvVariable.UninstallReturnCode] == NOT_RUN)

        # Ensure the handler status and ext_status is successful
        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.1")
        self._assert_ext_status(protocol.report_vm_status, "success", 0)

    def test_ext_path_and_version_env_variables_set_for_ever_operation(self, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        with patch.object(CGroupConfigurator.get_instance(), "start_extension_command") as patch_start_cmd:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            # Extension Path and Version should be set for all launch_command calls
            for args, kwargs in patch_start_cmd.call_args_list:
                self.assertIn(ExtCommandEnvVariable.ExtensionPath, kwargs['env'])
                self.assertIn('OSTCExtensions.ExampleHandlerLinux-1.0.0',
                              kwargs['env'][ExtCommandEnvVariable.ExtensionPath])
                self.assertIn(ExtCommandEnvVariable.ExtensionVersion, kwargs['env'])
                self.assertEqual("1.0.0", kwargs['env'][ExtCommandEnvVariable.ExtensionVersion])

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")

    @patch("azurelinuxagent.ga.cgroupconfigurator.handle_process_completion", side_effect="Process Successful")
    def test_ext_sequence_no_should_be_set_for_every_command_call(self, _, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_MULTIPLE_EXT)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        with patch("subprocess.Popen") as patch_popen:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

            for _, kwargs in patch_popen.call_args_list:
                self.assertIn(ExtCommandEnvVariable.ExtensionSeqNumber, kwargs['env'])
                self.assertEqual(kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber], "0")

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")

        # Next incarnation and seq for extensions, update version
        test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
        test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
        test_data.ext_conf = test_data.ext_conf.replace('seqNo="0"', 'seqNo="1"')
        test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=no-value-for-parameter

        with patch("subprocess.Popen") as patch_popen:
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

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

        base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.0')
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)
        self.create_script(os.path.join(base_dir, test_file_name), test_file)

        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_EXT_SINGLE)
        exthandlers_handler, protocol = self._create_mock(test_data, *args)  # pylint: disable=unused-variable,no-value-for-parameter
        expected_seq_no = 0

        with patch.object(ExtHandlerInstance, "load_manifest", return_value=manifest):
            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                for _, kwargs in mock_report_event.call_args_list:
                    # The output is of the format - 'Command: testfile.sh -{Operation} \n[stdout]ConfigSequenceNumber=N\n[stderr]'
                    if ("Command: " + test_file_name) not in kwargs['message']:
                        continue
                    self.assertIn("{0}={1}".format(ExtCommandEnvVariable.ExtensionSeqNumber, expected_seq_no),
                                  kwargs['message'])

            # Update goal state, extension version and seq no
            test_data.goal_state = test_data.goal_state.replace("<Incarnation>1<", "<Incarnation>2<")
            test_data.ext_conf = test_data.ext_conf.replace('version="1.0.0"', 'version="1.0.1"')
            test_data.ext_conf = test_data.ext_conf.replace('seqNo="0"', 'seqNo="1"')
            test_data.manifest = test_data.manifest.replace('1.0.0', '1.0.1')
            expected_seq_no = 1
            base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.1')
            if not os.path.exists(base_dir):
                os.mkdir(base_dir)
            self.create_script(os.path.join(base_dir, test_file_name), test_file)

            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

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

        error_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.0')
        if not os.path.exists(error_dir):
            os.mkdir(error_dir)
        self.create_script(os.path.join(error_dir, test_error_file_name), test_error_content)

        test_data, exthandlers_handler, protocol = self._set_up_update_test_and_update_gs(Mock(), *args)  # pylint: disable=unused-variable

        base_dir = os.path.join(conf.get_lib_dir(), 'OSTCExtensions.ExampleHandlerLinux-1.0.1')
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)
        self.create_script(os.path.join(base_dir, test_file_name), test_file)

        with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.load_manifest", return_value=manifest):
            with patch.object(ExtHandlerInstance, 'report_event') as mock_report_event:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                update_kwargs = next(kwargs for _, kwargs in mock_report_event.call_args_list if
                                     "Command: testfile.sh -update" in kwargs['message'])
                install_kwargs = next(kwargs for _, kwargs in mock_report_event.call_args_list if
                                      "Command: testfile.sh -install" in kwargs['message'])
                enable_kwargs = next(kwargs for _, kwargs in mock_report_event.call_args_list if
                                     "Command: testfile.sh -enable" in kwargs['message'])

                self.assertIn("%s=%s" % (ExtCommandEnvVariable.DisableReturnCode, exit_code), update_kwargs['message'])
                self.assertIn("%s=%s" % (ExtCommandEnvVariable.UninstallReturnCode, exit_code), install_kwargs['message'])
                self.assertIn("%s=%s" % (ExtCommandEnvVariable.UninstallReturnCode, exit_code), enable_kwargs['message'])

    def test_it_should_persist_goal_state_aggregate_status_until_new_incarnation(self, mock_get, mock_crypt_util, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        args, _ = protocol.report_vm_status.call_args
        gs_aggregate_status = args[0].vmAgent.vm_artifacts_aggregate_status.goal_state_aggregate_status
        self.assertIsNotNone(gs_aggregate_status, "Goal State Aggregate status not reported")
        self.assertEqual(gs_aggregate_status.status, GoalStateStatus.Success, "Wrong status reported")
        self.assertEqual(gs_aggregate_status.in_svd_seq_no, "1", "Incorrect seq no")

        # Update incarnation and ensure the gs_aggregate_status is modified too
        test_data.set_incarnation(2)
        protocol.client.update_goal_state()
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        self._assert_handler_status(protocol.report_vm_status, "Ready", expected_ext_count=1, version="1.0.0")
        args, _ = protocol.report_vm_status.call_args
        new_gs_aggregate_status = args[0].vmAgent.vm_artifacts_aggregate_status.goal_state_aggregate_status
        self.assertIsNotNone(new_gs_aggregate_status, "New Goal State Aggregate status not reported")
        self.assertNotEqual(gs_aggregate_status, new_gs_aggregate_status, "The gs_aggregate_status should be different")
        self.assertEqual(new_gs_aggregate_status.status, GoalStateStatus.Success, "Wrong status reported")
        self.assertEqual(new_gs_aggregate_status.in_svd_seq_no, "2", "Incorrect seq no")

    def test_it_should_parse_required_features_properly(self, mock_get, mock_crypt_util, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_REQUIRED_FEATURES)
        _, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

        required_features = protocol.get_goal_state().extensions_goal_state.required_features
        self.assertEqual(3, len(required_features), "Incorrect features parsed")
        for i, feature in enumerate(required_features):
            self.assertEqual(feature, "TestRequiredFeature{0}".format(i+1), "Name mismatch")

    def test_it_should_fail_goal_state_if_required_features_not_supported(self, mock_get, mock_crypt_util, *args):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE_REQUIRED_FEATURES)
        exthandlers_handler, protocol = self._create_mock(test_data, mock_get, mock_crypt_util, *args)

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        args, _ = protocol.report_vm_status.call_args
        gs_aggregate_status = args[0].vmAgent.vm_artifacts_aggregate_status.goal_state_aggregate_status
        self.assertEqual(0, len(args[0].vmAgent.extensionHandlers), "No extensions should be reported")
        self.assertIsNotNone(gs_aggregate_status, "GS Aggregagte status should be reported")
        self.assertEqual(gs_aggregate_status.status, GoalStateStatus.Failed, "GS should be failed")
        self.assertEqual(gs_aggregate_status.code, GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures,
                         "Incorrect error code set properly for GS failure")
        self.assertEqual(gs_aggregate_status.in_svd_seq_no, "1", "Sequence Number is wrong")


@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionSequencing(AgentTestCase):

    def _create_mock(self, mock_http_get, MockCryptUtil):
        test_data = wire_protocol_data.WireProtocolData(wire_protocol_data.DATA_FILE)

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(KNOWN_WIRESERVER_IP)
        protocol.detect()
        protocol.report_vm_status = MagicMock()

        handler = get_exthandlers_handler(protocol)

        return handler

    def _set_dependency_levels(self, dependency_levels, exthandlers_handler):
        """
        Creates extensions with the given dependencyLevel
        """
        handler_map = {}
        all_handlers = []
        for handler_name, level in dependency_levels:
            if handler_map.get(handler_name) is None:
                handler = Extension(name=handler_name)
                extension = ExtensionSettings(name=handler_name)
                handler.state = ExtensionRequestedState.Enabled
                handler.settings.append(extension)
                handler_map[handler_name] = handler
                all_handlers.append(handler)

            handler = handler_map[handler_name]
            for ext in handler.settings:
                ext.dependencyLevel = level

        exthandlers_handler.protocol.get_goal_state().extensions_goal_state._extensions *= 0
        exthandlers_handler.protocol.get_goal_state().extensions_goal_state.extensions.extend(all_handlers)

    def _validate_extension_sequence(self, expected_sequence, exthandlers_handler):
        installed_extensions = [a[0].ext_handler.name for a, _ in exthandlers_handler.handle_ext_handler.call_args_list]
        self.assertListEqual(expected_sequence, installed_extensions,
                             "Expected and actual list of extensions are not equal")

    def _run_test(self, extensions_to_be_failed, expected_sequence, exthandlers_handler):
        """
        Mocks get_ext_handling_status() to mimic error status for a given extension.
        Calls ExtHandlersHandler.run()
        Verifies if the ExtHandlersHandler.handle_ext_handler() was called with appropriate extensions
        in the expected order.
        """

        def get_ext_handling_status(ext):
            status = "error" if ext.name in extensions_to_be_failed else "success"
            return status

        exthandlers_handler.handle_ext_handler = MagicMock()

        with patch.object(ExtHandlerInstance, "get_ext_handling_status", side_effect=get_ext_handling_status):
            with patch.object(ExtHandlerInstance, "get_handler_status", ExtHandlerStatus):
                with patch('azurelinuxagent.ga.exthandlers._DEFAULT_EXT_TIMEOUT_MINUTES', 0.01):
                    exthandlers_handler.run()

                    self._validate_extension_sequence(expected_sequence, exthandlers_handler)

    def test_handle_ext_handlers(self, *args):
        """
        Tests extension sequencing among multiple extensions with dependencies.
        This test introduces failure in all possible levels and extensions.
        Verifies that the sequencing is in the expected order and a failure in one extension
        skips the rest of the extensions in the sequence.
        """
        exthandlers_handler = self._create_mock(*args)  # pylint: disable=no-value-for-parameter

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
        """
        Tests extension sequencing among multiple extensions with dependencies when
        some extension are to be uninstalled.
        Verifies that the sequencing is in the expected order and the uninstallation takes place
        prior to all the installation/enable.
        """
        exthandlers_handler = self._create_mock(*args)  # pylint: disable=no-value-for-parameter

        # "A", "D" and "F" are marked as to be uninstalled
        self._set_dependency_levels([("A", 0), ("B", 2), ("C", 2), ("D", 0), ("E", 1), ("F", 0), ("G", 1)],
                                    exthandlers_handler)

        extensions_to_be_failed = []
        expected_sequence = ["A", "D", "F", "E", "G", "B", "C"]
        self._run_test(extensions_to_be_failed, expected_sequence, exthandlers_handler)

    def test_handle_ext_handlers_fallback(self, *args):
        """
        This test makes sure that the extension sequencing is applied only when the user specifies
        dependency information in the extension.
        When there is no dependency specified, the agent is expected to assign dependencyLevel=0 to all extension.
        Also, it is expected to install all the extension no matter if there is any failure in any of the extensions.
        """
        exthandlers_handler = self._create_mock(*args)  # pylint: disable=no-value-for-parameter

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


class TestExtensionUpdateOnFailure(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.0001))
        self.mock_sleep.start()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

    @staticmethod
    def _do_upgrade_scenario_and_get_order(first_ext, upgraded_ext):
        """
        Given the provided ExtensionEmulator objects, installs the first and then attempts to
        update to the second.

        StatusBlobs and command invocations for each actor can be checked with
        {emulator}.status_blobs and {emulator}.actions[{command_name}] respectively.

        Note that this method assumes the first extension's install command should
        succeed. Don't use this method if your test is attempting to emulate a fresh install
        (i.e. not an upgrade) with a failing install.
        """

        with mock_wire_protocol(DATA_FILE, http_put_handler=generate_put_handler(first_ext, upgraded_ext)) as protocol:
            exthandlers_handler = get_exthandlers_handler(protocol)

            with enable_invocations(first_ext, upgraded_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),

                    # Note that if installCommand is supposed to fail, this will erroneously raise.
                    (first_ext, ExtensionCommandNames.ENABLE)
                )

            protocol.mock_wire_data.set_extensions_config_version(upgraded_ext.version)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()

            with enable_invocations(first_ext, upgraded_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()


                return invocation_record

    def test_non_enabled_ext_should_not_be_disabled_at_ver_update(self):
        _, enable_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(enable_action=enable_action)
        second_ext = extension_emulator(version="1.1.0")

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

    def test_disable_failed_env_variable_should_be_set_for_update_cmd_when_continue_on_update_failure_is_true(self):
        exit_code, disable_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(disable_action=disable_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=True)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

        _, kwargs = second_ext.actions[ExtensionCommandNames.UPDATE].call_args

        self.assertEqual(kwargs["env"][ExtCommandEnvVariable.DisableReturnCode], exit_code,
            "DisableAction's return code should be in updateAction's env.")

    def test_uninstall_failed_env_variable_should_set_for_install_when_continue_on_update_failure_is_true(self):
        exit_code, uninstall_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(uninstall_action=uninstall_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=True)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

        _, kwargs = second_ext.actions[ExtensionCommandNames.INSTALL].call_args

        self.assertEqual(kwargs["env"][ExtCommandEnvVariable.UninstallReturnCode], exit_code,
            "UninstallAction's return code should be in updateAction's env.")


    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_disable_failure(self):
        exit_code, disable_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(disable_action=disable_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=False)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE)
        )

        self.assertEqual(len(first_ext.status_blobs), 1, "The first extension should not have submitted a second status.")
        self.assertEqual(len(second_ext.status_blobs), 1, "The second extension should have a single submitted status.")
        self.assertTrue(exit_code in second_ext.status_blobs[0]["formattedMessage"]["message"],
            "DisableAction's error code should be propagated to the status blob.")


    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_false_on_uninstall_failure(self):
        exit_code, uninstall_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(uninstall_action=uninstall_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=False)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL)
        )

        self.assertEqual(len(first_ext.status_blobs), 1, "The first extension should not have submitted a second status.")
        self.assertEqual(len(second_ext.status_blobs), 1, "The second extension should have a single submitted status.")
        self.assertTrue(exit_code in second_ext.status_blobs[0]["formattedMessage"]["message"],
            "UninstallAction's error code should be propagated to the status blob.")

    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_true_on_disable_and_update_failure(self):
        exit_codes = { }

        exit_codes["disable"], disable_action = Actions.generate_unique_fail()
        exit_codes["update"], update_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(disable_action=disable_action)
        second_ext = extension_emulator(version="1.1.0", update_action=update_action,
            continue_on_update_failure=True)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE)
        )

        self.assertEqual(len(first_ext.status_blobs), 1, "The first extension should not have submitted a second status.")
        self.assertEqual(len(second_ext.status_blobs), 1, "The second extension should have a single submitted status.")
        self.assertTrue(exit_codes["update"] in second_ext.status_blobs[0]["formattedMessage"]["message"],
            "UpdateAction's error code should be propagated to the status blob.")


    def test_extension_error_should_be_raised_when_continue_on_update_failure_is_true_on_uninstall_and_install_failure(self):
        exit_codes = { }

        exit_codes["install"], install_action = Actions.generate_unique_fail()
        exit_codes["uninstall"], uninstall_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(uninstall_action=uninstall_action)
        second_ext = extension_emulator(version="1.1.0", install_action=install_action,
            continue_on_update_failure=True)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL)
        )

        self.assertEqual(len(first_ext.status_blobs), 1, "The first extension should not have submitted a second status.")
        self.assertEqual(len(second_ext.status_blobs), 1, "The second extension should have a single submitted status.")
        self.assertTrue(exit_codes["install"] in second_ext.status_blobs[0]["formattedMessage"]["message"],
            "InstallAction's error code should be propagated to the status blob.")


    def test_failed_env_variables_should_be_set_from_within_extension_commands(self):
        """
        This test will test from the perspective of the extensions command weather the env variables are
        being set for those processes
        """
        exit_codes = { }

        exit_codes["disable"], disable_action = Actions.generate_unique_fail()
        exit_codes["uninstall"], uninstall_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(disable_action=disable_action, uninstall_action=uninstall_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=True)

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

        _, update_kwargs = second_ext.actions[ExtensionCommandNames.UPDATE].call_args
        _, install_kwargs = second_ext.actions[ExtensionCommandNames.INSTALL].call_args

        second_extension_dir = os.path.join(
            conf.get_lib_dir(), "{0}-{1}".format(second_ext.name, second_ext.version)
        )

        # Ensure we're checking variables for update scenario
        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.DisableReturnCode], exit_codes["disable"],
            "DisableAction's return code should be present in updateAction's env.")
        self.assertTrue(ExtCommandEnvVariable.UninstallReturnCode not in update_kwargs["env"],
            "UninstallAction's return code should not be in updateAction's env.")
        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.ExtensionPath], second_extension_dir,
            "The second extension's directory should be present in updateAction's env.")
        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.ExtensionVersion], "1.1.0",
            "The second extension's version should be present in updateAction's env.")

        # Ensure we're checking variables for install scenario
        self.assertEqual(install_kwargs["env"][ExtCommandEnvVariable.UninstallReturnCode], exit_codes["uninstall"],
            "UninstallAction's return code should be present in installAction's env.")
        self.assertTrue(ExtCommandEnvVariable.DisableReturnCode not in install_kwargs["env"],
            "DisableAction's return code should not be in installAction's env.")
        self.assertEqual(install_kwargs["env"][ExtCommandEnvVariable.ExtensionPath], second_extension_dir,
            "The second extension's directory should be present in installAction's env.")
        self.assertEqual(install_kwargs["env"][ExtCommandEnvVariable.ExtensionVersion], "1.1.0",
            "The second extension's version should be present in installAction's env.")


    def test_correct_exit_code_should_set_on_disable_cmd_failure(self):
        exit_code, disable_action = Actions.generate_unique_fail()

        first_ext = extension_emulator(disable_action=disable_action)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=True,
            update_mode="UpdateWithoutInstall")

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

        _, update_kwargs = second_ext.actions[ExtensionCommandNames.UPDATE].call_args

        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.DisableReturnCode], exit_code,
            "DisableAction's return code should be present in UpdateAction's env.")

    def test_timeout_code_should_set_on_cmd_timeout(self):
        # Return None to every poll, forcing a timeout after 900 seconds (actually very quick because sleep(*) is mocked)
        force_timeout = lambda *args, **kwargs: None

        first_ext = extension_emulator(disable_action=force_timeout, uninstall_action=force_timeout)
        second_ext = extension_emulator(version="1.1.0", continue_on_update_failure=True)

        with patch("os.killpg"):
            with patch("os.getpgid"):
                invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )


        _, update_kwargs = second_ext.actions[ExtensionCommandNames.UPDATE].call_args
        _, install_kwargs = second_ext.actions[ExtensionCommandNames.INSTALL].call_args

        # Verify both commands are reported as timeouts.
        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.DisableReturnCode], str(ExtensionErrorCodes.PluginHandlerScriptTimedout),
            "DisableAction's return code should be marked as a timeout in UpdateAction's env.")
        self.assertEqual(install_kwargs["env"][ExtCommandEnvVariable.UninstallReturnCode], str(ExtensionErrorCodes.PluginHandlerScriptTimedout),
            "UninstallAction's return code should be marked as a timeout in installAction's env.")


    def test_success_code_should_set_in_env_variables_on_cmd_success(self):

        first_ext = extension_emulator()
        second_ext = extension_emulator(version="1.1.0")

        invocation_record = TestExtensionUpdateOnFailure._do_upgrade_scenario_and_get_order(first_ext, second_ext)

        invocation_record.compare(
            (first_ext, ExtensionCommandNames.DISABLE),
            (second_ext, ExtensionCommandNames.UPDATE),
            (first_ext, ExtensionCommandNames.UNINSTALL),
            (second_ext, ExtensionCommandNames.INSTALL),
            (second_ext, ExtensionCommandNames.ENABLE)
        )

        _, update_kwargs = second_ext.actions[ExtensionCommandNames.UPDATE].call_args
        _, install_kwargs = second_ext.actions[ExtensionCommandNames.INSTALL].call_args

        self.assertEqual(update_kwargs["env"][ExtCommandEnvVariable.DisableReturnCode], "0",
            "DisableAction's return code in updateAction's env should be 0.")
        self.assertEqual(install_kwargs["env"][ExtCommandEnvVariable.UninstallReturnCode], "0",
            "UninstallAction's return code in installAction's env should be 0.")


class TestCollectExtensionStatus(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.lib_dir = tempfile.mkdtemp()
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.001))
        self.mock_sleep.start()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

    def _setup_extension_for_validating_collect_ext_status(self, mock_lib_dir, status_file=None):
        handler_name = "TestHandler"
        handler_version = "1.0.0"
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(os.path.join(self.lib_dir, handler_name + "-" + handler_version, "config"))
        fileutil.mkdir(os.path.join(self.lib_dir, handler_name + "-" + handler_version, "status"))
        shutil.copy(tempfile.mkstemp(prefix="test-file")[1],
                    os.path.join(self.lib_dir, handler_name + "-" + handler_version, "config", "0.settings"))

        if status_file is not None:
            shutil.copy(os.path.join(data_dir, "ext", status_file),
                        os.path.join(self.lib_dir, handler_name + "-" + handler_version, "status", "0.status"))

        with mock_wire_protocol(DATA_FILE) as protocol:
            exthandler = Extension(name=handler_name)
            exthandler.version = handler_version
            extension = ExtensionSettings(name=handler_name, sequenceNumber=0)
            exthandler.settings.append(extension)

            return ExtHandlerInstance(exthandler, protocol), extension

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status(self, mock_lib_dir):
        """
        This test validates that collect_ext_status correctly picks up the status file (sample-status.json) and then
        parses it correctly.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status.json")
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertEqual(ext_status.message, "Aenean semper nunc nisl, vitae sollicitudin felis consequat at. In "
                                             "lobortis elementum sapien, non commodo odio semper ac.")
        self.assertEqual(ext_status.status, ExtensionStatusValue.success)

        self.assertEqual(len(ext_status.substatusList), 1)
        sub_status = ext_status.substatusList[0]
        self.assertEqual(sub_status.code, "0")
        self.assertEqual(sub_status.message, None)
        self.assertEqual(sub_status.status, ExtensionStatusValue.success)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_for_invalid_json(self, mock_lib_dir):
        """
        This test validates that collect_ext_status correctly picks up the status file (sample-status-invalid-json-format.json)
        and then since the Json cannot be parsed correctly it extension status message should include 2000 bytes of status file
        and the line number in which it failed to parse. The uniqueMachineId tag comes from status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status-invalid-json-format.json")
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSettingsStatusInvalid)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, r".*The status reported by the extension TestHandler-1.0.0\(Sequence number 0\), "
                                             r"was in an incorrect format and the agent could not parse it correctly."
                                             r" Failed due to.*")
        self.assertIn("\"uniqueMachineId\": \"e5e5602b-48a6-4c35-9f96-752043777af1\"", ext_status.message)
        self.assertEqual(ext_status.status, ExtensionStatusValue.error)
        self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_it_should_collect_ext_status_even_when_config_dir_deleted(self, mock_lib_dir):

        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status.json")

        shutil.rmtree(ext_handler_i.get_conf_dir(), ignore_errors=True)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertEqual(ext_status.message, "Aenean semper nunc nisl, vitae sollicitudin felis consequat at. In "
                                             "lobortis elementum sapien, non commodo odio semper ac.")
        self.assertEqual(ext_status.status, ExtensionStatusValue.success)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_very_large_status_message(self, mock_lib_dir):
        """
        Testing collect_ext_status() with a very large status file (>128K) to see if it correctly parses the status
        without generating a really large message.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                                                                           "sample-status-very-large.json")
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        # [TRUNCATED] comes from azurelinuxagent.ga.exthandlers._TRUNCATED_SUFFIX
        self.assertRegex(ext_status.message, r"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum non "
                                             r"lacinia urna, sit .*\[TRUNCATED\]")
        self.maxDiff = None
        self.assertEqual(ext_status.status, ExtensionStatusValue.success)
        self.assertEqual(len(ext_status.substatusList), 1) # NUM OF SUBSTATUS PARSED
        for sub_status in ext_status.substatusList:
            self.assertRegex(sub_status.name, r'\[\{"status"\: \{"status": "success", "code": "1", "snapshotInfo": '
                                              r'\[\{"snapshotUri":.*')
            self.assertEqual(0, sub_status.code)
            self.assertRegex(sub_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
                                                 "non lacinia urna, sit amet venenatis orci.*")
            self.assertEqual(sub_status.status, ExtensionStatusValue.success)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_very_large_status_file_with_multiple_substatus_nodes(self, mock_lib_dir):
        """
        Testing collect_ext_status() with a very large status file (>128K) to see if it correctly parses the status
        without generating a really large message. This checks if the multiple substatus messages are correctly parsed
        and truncated.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(
            mock_lib_dir, "sample-status-very-large-multiple-substatuses.json")  # ~470K bytes.
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, SUCCESS_CODE_FROM_STATUS_FILE)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, "Enable")
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                                             "Vestibulum non lacinia urna, sit .*")
        self.assertEqual(ext_status.status, ExtensionStatusValue.success)
        self.assertEqual(len(ext_status.substatusList), 12)  # The original file has 41 substatus nodes.
        for sub_status in ext_status.substatusList:
            self.assertRegex(sub_status.name, r'\[\{"status"\: \{"status": "success", "code": "1", "snapshotInfo": '
                                              r'\[\{"snapshotUri":.*')
            self.assertEqual(0, sub_status.code)
            self.assertRegex(sub_status.message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
                                                 "non lacinia urna, sit amet venenatis orci.*")
            self.assertEqual(ExtensionStatusValue.success, sub_status.status)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_read_file_read_exceptions(self, mock_lib_dir):
        """
        Testing collect_ext_status to validate the readfile exceptions.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir, "sample-status.json")
        original_read_file = read_file

        def mock_read_file(file_, *args, **kwargs):
            expected_status_file_path = os.path.join(self.lib_dir,
                                                     ext_handler_i.ext_handler.name + "-" +
                                                     ext_handler_i.ext_handler.version,
                                                     "status", "0.status")
            if file_ == expected_status_file_path:
                raise IOError("No such file or directory: {0}".format(expected_status_file_path))
            else:
                original_read_file(file_, *args, **kwargs)

        with patch('azurelinuxagent.common.utils.fileutil.read_file', mock_read_file):
            ext_status = ext_handler_i.collect_ext_status(extension)

            self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginUnknownFailure)
            self.assertEqual(ext_status.configurationAppliedTime, None)
            self.assertEqual(ext_status.operation, None)
            self.assertEqual(ext_status.sequenceNumber, 0)
            self.assertRegex(ext_status.message, r".*We couldn't read any status for {0}-{1} extension, for the "
                                                 r"sequence number {2}. It failed due to".
                             format("TestHandler", "1.0.0", 0))
            self.assertEqual(ext_status.status, ExtensionStatusValue.error)
            self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_json_exceptions(self, mock_lib_dir):
        """
        Testing collect_ext_status() with a malformed json status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                        "sample-status-invalid-format-emptykey-line7.json")
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSettingsStatusInvalid)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, r".*The status reported by the extension {0}-{1}\(Sequence number {2}\), "
                                             "was in an incorrect format and the agent could not parse it correctly."
                                             " Failed due to.*".
                         format("TestHandler", "1.0.0", 0))
        self.assertEqual(ext_status.status, ExtensionStatusValue.error)
        self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_ext_status_parse_ext_status_exceptions(self, mock_lib_dir):
        """
        Testing collect_ext_status() with a malformed json status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir,
                                        "sample-status-invalid-status-no-status-status-key.json")
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSettingsStatusInvalid)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertRegex(ext_status.message, "Could not get a valid status from the extension {0}-{1}. "
                                             "Encountered the following error".format("TestHandler", "1.0.0"))
        self.assertEqual(ext_status.status, ExtensionStatusValue.error)
        self.assertEqual(len(ext_status.substatusList), 0)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_it_should_report_transitioning_if_status_file_not_found(self, mock_lib_dir):
        """
        Testing collect_ext_status() with a missing status file.
        """
        ext_handler_i, extension = self._setup_extension_for_validating_collect_ext_status(mock_lib_dir)
        ext_status = ext_handler_i.collect_ext_status(extension)

        self.assertEqual(ext_status.code, ExtensionErrorCodes.PluginSuccess)
        self.assertEqual(ext_status.configurationAppliedTime, None)
        self.assertEqual(ext_status.operation, None)
        self.assertEqual(ext_status.sequenceNumber, 0)
        self.assertIn("This status is being reported by the Guest Agent since no status file was reported by extension {0}".
                      format("TestHandler"), ext_status.message)
        self.assertEqual(ext_status.status, ExtensionStatusValue.transitioning)
        self.assertEqual(len(ext_status.substatusList), 0)


class TestAdditionalLocationsExtensions(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        self.test_data = DATA_FILE_EXT_ADDITIONAL_LOCATIONS.copy()

    def tearDown(self):
        AgentTestCase.tearDown(self)

    @patch('time.sleep')
    def test_additional_locations_node_is_consumed(self, _):

        location_uri_pattern = r'https?://mock-goal-state/(?P<location_type>{0})/(?P<manifest_num>\d)/manifest.xml'\
            .format(r'(location)|(failoverlocation)|(additionalLocation)')
        location_uri_regex = re.compile(location_uri_pattern)

        manifests_used = [ ('location', '1'), ('failoverlocation', '2'),
            ('additionalLocation', '3'), ('additionalLocation', '4') ]

        def manifest_location_handler(url, **kwargs):
            url_match = location_uri_regex.match(url)

            if not url_match:
                if "extensionArtifact" in url:
                    wrapped_url = kwargs.get("headers", {}).get("x-ms-artifact-location")

                    if wrapped_url and location_uri_regex.match(wrapped_url):
                        return Exception("Ignoring host plugin requests for testing purposes.")

                return None

            location_type, manifest_num = url_match.group("location_type", "manifest_num")

            try:
                manifests_used.remove((location_type, manifest_num))
            except ValueError:
                raise AssertionError("URI '{0}' used multiple times".format(url))

            if manifests_used:
                # Still locations to try in the list; throw a fake
                # error to make sure all of the locations get called.
                return Exception("Failing manifest fetch from uri '{0}' for testing purposes.".format(url))

            return None


        with mock_wire_protocol(self.test_data, http_get_handler=manifest_location_handler) as protocol:
            exthandlers_handler = get_exthandlers_handler(protocol)
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()

    def test_fetch_manifest_timeout_is_respected(self):

        location_uri_pattern = r'https?://mock-goal-state/(?P<location_type>{0})/(?P<manifest_num>\d)/manifest.xml'\
            .format(r'(location)|(failoverlocation)|(additionalLocation)')
        location_uri_regex = re.compile(location_uri_pattern)

        def manifest_location_handler(url, **kwargs):
            url_match = location_uri_regex.match(url)

            if not url_match:
                if "extensionArtifact" in url:
                    wrapped_url = kwargs.get("headers", {}).get("x-ms-artifact-location")

                    if wrapped_url and location_uri_regex.match(wrapped_url):
                        return Exception("Ignoring host plugin requests for testing purposes.")

                return None

            if manifest_location_handler.num_times_called == 0:
                time.sleep(.3)
                manifest_location_handler.num_times_called += 1
                return Exception("Failing manifest fetch from uri '{0}' for testing purposes.".format(url))

            return None

        manifest_location_handler.num_times_called = 0

        with mock_wire_protocol(self.test_data, http_get_handler=manifest_location_handler) as protocol:
            ext_handlers = protocol.get_goal_state().extensions_goal_state.extensions

            download_timeout = wire._DOWNLOAD_TIMEOUT
            wire._DOWNLOAD_TIMEOUT = datetime.timedelta(minutes=0)
            try:
                with self.assertRaises(ExtensionDownloadError):
                    protocol.client.fetch_manifest("extension", ext_handlers[0].manifest_uris, use_verify_header=False)
            finally:
                wire._DOWNLOAD_TIMEOUT = download_timeout


# New test cases should be added here.This class uses mock_wire_protocol
class TestExtension(TestExtensionBase, HttpRequestPredicates):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        cls.mock_sleep = patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
        cls.mock_sleep.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_sleep.stop()

    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    @patch('time.gmtime', MagicMock(return_value=time.gmtime(0)))
    @patch("azurelinuxagent.common.version.get_daemon_version", return_value=FlexibleVersion("0.0.0.0"))
    def test_ext_handler_reporting_status_file(self, _):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:

            def mock_http_put(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            protocol.aggregate_status = None
            protocol.set_http_handlers(http_put_handler=mock_http_put)
            exthandlers_handler = get_exthandlers_handler(protocol)

            # creating supported features list that is sent to crp
            supported_features = []
            for _, feature in get_agent_supported_features_list_for_crp().items():
                supported_features.append(
                    {
                        "Key": feature.name,
                        "Value": feature.version
                    }
                )

            expected_status = {
                "__comment__": "The __status__ property is the actual status reported to CRP",
                "__status__": {
                    "version": "1.1",
                    "timestampUTC": "1970-01-01T00:00:00Z",
                    "aggregateStatus": {
                        "guestAgentStatus": {
                            "version": AGENT_VERSION,
                            "status": "Ready",
                            "formattedMessage": {
                                "lang": "en-US",
                                "message": "Guest Agent is running"
                            }
                        },
                        "handlerAggregateStatus": [
                            {
                                "handlerVersion": "1.0.0",
                                "handlerName": "OSTCExtensions.ExampleHandlerLinux",
                                "status": "Ready",
                                "code": 0,
                                "useExactVersion": True,
                                "formattedMessage": {
                                    "lang": "en-US",
                                    "message": "Plugin enabled"
                                },
                                "runtimeSettingsStatus": {
                                    "settingsStatus": {
                                        "status": {
                                            "name": "OSTCExtensions.ExampleHandlerLinux",
                                            "configurationAppliedTime": None,
                                            "operation": None,
                                            "status": "success",
                                            "code": 0,
                                            "formattedMessage": {
                                                "lang": "en-US",
                                                "message": None
                                            }
                                        },
                                        "version": 1.0,
                                        "timestampUTC": "1970-01-01T00:00:00Z"
                                    },
                                    "sequenceNumber": 0
                                }
                            }
                        ],
                        "vmArtifactsAggregateStatus": {
                            "goalStateAggregateStatus": {
                                "formattedMessage": {
                                    "lang": "en-US",
                                    "message": "GoalState executed successfully"
                                },
                                "timestampUTC": "1970-01-01T00:00:00Z",
                                "inSvdSeqNo": "1",
                                "status": "Success",
                                "code": 0
                            }
                        }
                    },
                    "guestOSInfo": None,
                    "supportedFeatures": supported_features
                },
                "__debug__": {
                    "agentName": AGENT_NAME,
                    "daemonVersion": "0.0.0.0",
                    "pythonVersion": "Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO),
                    "extensionSupportedFeatures": [name for name, _ in get_agent_supported_features_list_for_extensions().items()],
                    "supportsMultiConfig": {
                        "OSTCExtensions.ExampleHandlerLinux": False
                    }
                }
            }


            exthandlers_handler.run()
            vm_status = exthandlers_handler.report_ext_handlers_status()
            actual_status_json = json.loads(exthandlers_handler.get_ext_handlers_status_debug_info(vm_status))

            # Don't compare the guestOSInfo
            status_property = actual_status_json.get("__status__")
            self.assertIsNotNone(status_property, "The status file is missing the __status__ property")
            self.assertIsNotNone(status_property.get("guestOSInfo"), "The status file is missing the guestOSInfo property")
            status_property["guestOSInfo"] = None

            actual_status_json.pop('guestOSInfo', None)

            self.assertEqual(expected_status, actual_status_json)

    def test_it_should_process_extensions_only_if_allowed(self):
        def assert_extensions_called(exthandlers_handler, expected_call_count=0):
            extension_name = 'OSTCExtensions.ExampleHandlerLinux'
            extension_calls = []
            original_popen = subprocess.Popen

            def mock_popen(*args, **kwargs):
                if extension_name in args[0]:
                    extension_calls.append(args[0])
                return original_popen(*args, **kwargs)

            with patch('subprocess.Popen', side_effect=mock_popen):
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                self.assertEqual(expected_call_count, len(extension_calls), "Call counts dont match")

        with patch('time.sleep', side_effect=lambda _: mock_sleep(0.001)):
            def http_get_handler(url, *_, **kwargs):
                if self.is_in_vm_artifacts_profile_request(url) or self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                    return mock_in_vm_artifacts_profile_response
                return None

            mock_in_vm_artifacts_profile_response = MockHttpResponse(200, body='{ "onHold": false }'.encode('utf-8'))

            with mock_wire_protocol(wire_protocol_data.DATA_FILE_IN_VM_ARTIFACTS_PROFILE, http_get_handler=http_get_handler) as protocol:
                protocol.report_vm_status = MagicMock()
                exthandlers_handler = get_exthandlers_handler(protocol)

                # Extension called once for Install and once for Enable
                assert_extensions_called(exthandlers_handler, expected_call_count=2)
                self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")

                # Update GoalState
                protocol.mock_wire_data.set_incarnation(2)
                protocol.client.update_goal_state()

                with patch.object(conf, 'get_extensions_enabled', return_value=False):
                    assert_extensions_called(exthandlers_handler, expected_call_count=0)

                # Disabled over-provisioning in configuration
                # In this case we should process GoalState as incarnation changed
                with patch.object(conf, 'get_extensions_enabled', return_value=True):
                    with patch.object(conf, 'get_enable_overprovisioning', return_value=False):
                        # 1 expected call count for Enable command
                        assert_extensions_called(exthandlers_handler, expected_call_count=1)

                # Enabled on_hold property in artifact_blob
                mock_in_vm_artifacts_profile_response = MockHttpResponse(200, body='{ "onHold": true }'.encode('utf-8'))
                protocol.client.reset_goal_state()

                with patch.object(conf, 'get_extensions_enabled', return_value=True):
                    with patch.object(conf, "get_enable_overprovisioning", return_value=True):
                        assert_extensions_called(exthandlers_handler, expected_call_count=0)

                # Disabled on_hold property in artifact_blob
                mock_in_vm_artifacts_profile_response = MockHttpResponse(200, body='{ "onHold": false }'.encode('utf-8'))
                protocol.client.reset_goal_state()

                with patch.object(conf, 'get_extensions_enabled', return_value=True):
                    with patch.object(conf, "get_enable_overprovisioning", return_value=True):
                        # 1 expected call count for Enable command
                        assert_extensions_called(exthandlers_handler, expected_call_count=1)

    def test_it_should_process_extensions_appropriately_on_artifact_hold(self):
        with patch('time.sleep', side_effect=lambda _: mock_sleep(0.001)):
            with patch("azurelinuxagent.common.conf.get_enable_overprovisioning", return_value=True):
                with mock_wire_protocol(wire_protocol_data.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
                    protocol.report_vm_status = MagicMock()
                    exthandlers_handler = get_exthandlers_handler(protocol)
                    #
                    # The test data sets onHold to True; extensions should not be processed
                    #
                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()

                    vm_agent_status = protocol.report_vm_status.call_args[0][0].vmAgent
                    self.assertEqual(vm_agent_status.status, "Ready", "Agent should report ready")
                    self.assertEqual(0, len(vm_agent_status.extensionHandlers), "No extensions should be reported as on_hold is True")
                    self.assertIsNone(vm_agent_status.vm_artifacts_aggregate_status.goal_state_aggregate_status, "No GS Aggregate status should be reported")

                    #
                    # Now force onHold to False; extensions should be processed
                    #
                    def http_get_handler(url, *_, **kwargs):
                        if self.is_in_vm_artifacts_profile_request(url) or self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                            return MockHttpResponse(200, body='{ "onHold": false }'.encode('utf-8'))
                        return None
                    protocol.set_http_handlers(http_get_handler=http_get_handler)

                    protocol.client.reset_goal_state()

                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()

                    self._assert_handler_status(protocol.report_vm_status, "Ready", 1, "1.0.0")
                    self.assertEqual("1", protocol.report_vm_status.call_args[0][0].vmAgent.vm_artifacts_aggregate_status.goal_state_aggregate_status.in_svd_seq_no, "SVD sequence number mismatch")

    def test_it_should_redact_access_tokens_in_extension_output(self):
        original = r'''ONE https://foo.blob.core.windows.net/bar?sv=2000&ss=bfqt&srt=sco&sp=rw&se=2025&st=2022&spr=https&sig=SI%3D
            TWO:HTTPS://bar.blob.core.com/foo/bar/foo.txt?sv=2018&sr=b&sig=Yx%3D&st=2023%3A52Z&se=9999%3A59%3A59Z&sp=r TWO
            https://bar.com/foo?uid=2018&sr=b THREE'''
        expected = r'''ONE https://foo.blob.core.windows.net/bar?<redacted>
            TWO:HTTPS://bar.blob.core.com/foo/bar/foo.txt?<redacted> TWO
            https://bar.com/foo?uid=2018&sr=b THREE'''

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            exthandlers_handler = get_exthandlers_handler(protocol)

            original_popen = subprocess.Popen

            def mock_popen(cmd, *args, **kwargs):
                if cmd.endswith("sample.py -enable"):
                    cmd = "echo '{0}'; >&2 echo '{0}'; exit 1".format(original)
                return original_popen(cmd, *args, **kwargs)

            with patch.object(subprocess, 'Popen', side_effect=mock_popen):
                exthandlers_handler.run()

            status = exthandlers_handler.report_ext_handlers_status()
            self.assertEqual(1, len(status.vmAgent.extensionHandlers), 'Expected exactly 1 extension status')
            message = status.vmAgent.extensionHandlers[0].message
            self.assertIn('[stdout]\n{0}'.format(expected), message, "The extension's stdout was not redacted correctly")
            self.assertIn('[stderr]\n{0}'.format(expected), message, "The extension's stderr was not redacted correctly")


if __name__ == '__main__':
    unittest.main()
