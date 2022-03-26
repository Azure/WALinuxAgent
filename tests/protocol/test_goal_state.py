# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import glob
import os
import re

from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.protocol.goal_state import GoalState, _GET_GOAL_STATE_MAX_ATTEMPTS
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import ARCHIVE_DIRECTORY_NAME
from tests.protocol.mocks import mock_wire_protocol, MockHttpResponse
from tests.protocol import mockwiredata
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates
from tests.tools import AgentTestCase, patch, load_data


class GoalStateTestCase(AgentTestCase):
    def test_fetch_goal_state_should_raise_on_incomplete_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.mock_wire_data.data_files = mockwiredata.DATA_FILE_NOOP_GS
            protocol.mock_wire_data.reload()
            protocol.mock_wire_data.set_incarnation(2)

            with patch('time.sleep') as mock_sleep:
                with self.assertRaises(ProtocolError):
                    GoalState(protocol.client)
                self.assertEqual(_GET_GOAL_STATE_MAX_ATTEMPTS, mock_sleep.call_count, "Unexpected number of retries")

    @patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=True)
    def test_instantiating_goal_state_should_save_the_goal_state_to_the_history_directory(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(999)
            protocol.mock_wire_data.set_etag(888)

            _ = GoalState(protocol.client)

            self._assert_directory_contents(
                self._find_history_subdirectory("999-888"),
                ["GoalState.xml", "ExtensionsConfig.xml", "VmSettings.json", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

    def _find_history_subdirectory(self, tag):
        matches = glob.glob(os.path.join(self.tmp_dir, ARCHIVE_DIRECTORY_NAME, "*_{0}".format(tag)))
        self.assertTrue(len(matches) == 1, "Expected one history directory for tag {0}. Got: {1}".format(tag, matches))
        return matches[0]

    def _assert_directory_contents(self, directory, expected_files):
        actual_files = os.listdir(directory)

        expected_files.sort()
        actual_files.sort()

        self.assertEqual(expected_files, actual_files, "The expected files were not saved to {0}".format(directory))

    @patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=True)
    def test_update_should_create_new_history_subdirectories(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(123)
            protocol.mock_wire_data.set_etag(654)

            goal_state = GoalState(protocol.client)
            self._assert_directory_contents(
                self._find_history_subdirectory("123-654"),
                ["GoalState.xml", "ExtensionsConfig.xml", "VmSettings.json", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

            def http_get_handler(url, *_, **__):
                if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
                    return MockHttpResponse(status=httpclient.NOT_MODIFIED)
                return None

            protocol.mock_wire_data.set_incarnation(234)
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            goal_state.update()
            self._assert_directory_contents(
                self._find_history_subdirectory("234-654"),
                ["GoalState.xml", "ExtensionsConfig.xml", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

            protocol.mock_wire_data.set_etag(987)
            protocol.set_http_handlers(http_get_handler=None)
            goal_state.update()
            self._assert_directory_contents(
                self._find_history_subdirectory("234-987"), ["VmSettings.json"])

    @patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=True)
    def test_it_should_redact_the_protected_settings_when_saving_to_the_history_directory(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(888)

            goal_state = GoalState(protocol.client)

            extensions_goal_state = goal_state.extensions_goal_state
            protected_settings = []
            for ext_handler in extensions_goal_state.extensions:
                for extension in ext_handler.settings:
                    if extension.protectedSettings is not None:
                        protected_settings.append(extension.protectedSettings)
            if len(protected_settings) == 0:
                raise Exception("The test goal state does not include any protected settings")

            history_directory = self._find_history_subdirectory("888-1")
            extensions_config_file = os.path.join(history_directory, "ExtensionsConfig.xml")
            vm_settings_file = os.path.join(history_directory, "VmSettings.json")
            for file_name in extensions_config_file, vm_settings_file:
                with open(file_name, "r") as stream:
                    file_contents = stream.read()

                    for settings in protected_settings:
                        self.assertNotIn(
                            settings,
                            file_contents,
                            "The protectedSettings should not have been saved to {0}".format(file_name))

                    matches = re.findall(r'"protectedSettings"\s*:\s*"\*\*\* REDACTED \*\*\*"', file_contents)
                    self.assertEqual(
                        len(matches),
                        len(protected_settings),
                        "Could not find the expected number of redacted settings in {0}.\nExpected {1}.\n{2}".format(file_name, len(protected_settings), file_contents))

    @patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=True)
    def test_it_should_save_vm_settings_on_parse_errors(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            invalid_vm_settings_file = "hostgaplugin/vm_settings-parse_error.json"
            data_file = mockwiredata.DATA_FILE_VM_SETTINGS.copy()
            data_file["vm_settings"] = invalid_vm_settings_file
            protocol.mock_wire_data = mockwiredata.WireProtocolData(data_file)
            protocol.mock_wire_data.set_etag(888)

            with self.assertRaises(ProtocolError):  # the parsing error will cause an exception
                _ = GoalState(protocol.client)

            history_directory = self._find_history_subdirectory("0")

            vm_settings_file = os.path.join(history_directory, "VmSettings.888.json")
            self.assertTrue(os.path.exists(vm_settings_file), "{0} was not saved".format(vm_settings_file))

            expected = load_data(invalid_vm_settings_file)
            actual = fileutil.read_file(vm_settings_file)

            self.assertEqual(expected, actual, "The vmSettings were not saved correctly")