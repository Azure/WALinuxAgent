# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import contextlib
import datetime
import glob
import os
import re
import time

from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource, GoalStateChannel
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

    def test_instantiating_goal_state_should_save_the_goal_state_to_the_history_directory(self):
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

    def test_update_should_create_new_history_subdirectories(self):
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

    def test_it_should_redact_the_protected_settings_when_saving_to_the_history_directory(self):
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

    def test_it_should_save_vm_settings_on_parse_errors(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            invalid_vm_settings_file = "hostgaplugin/vm_settings-parse_error.json"
            data_file = mockwiredata.DATA_FILE_VM_SETTINGS.copy()
            data_file["vm_settings"] = invalid_vm_settings_file
            protocol.mock_wire_data = mockwiredata.WireProtocolData(data_file)
            protocol.mock_wire_data.set_etag(888)

            with self.assertRaises(ProtocolError):  # the parsing error will cause an exception
                _ = GoalState(protocol.client)

            # Do an extra call to update the goal state; this should save the vmsettings to the history directory
            # only once (self._find_history_subdirectory asserts 1 single match)
            time.sleep(0.5)  # add a short delay to ensure that a new timestamp would be saved in the history folder
            with self.assertRaises(ProtocolError):
                _ = GoalState(protocol.client)

            history_directory = self._find_history_subdirectory("888")

            vm_settings_file = os.path.join(history_directory, "VmSettings.json")
            self.assertTrue(os.path.exists(vm_settings_file), "{0} was not saved".format(vm_settings_file))

            expected = load_data(invalid_vm_settings_file)
            actual = fileutil.read_file(vm_settings_file)

            self.assertEqual(expected, actual, "The vmSettings were not saved correctly")

    @staticmethod
    @contextlib.contextmanager
    def _create_protocol_ws_and_hgap_in_sync():
        """
        Creates a mock protocol in which the HostGAPlugin and the WireServer are in sync, both of them returning
        the same Fabric goal state.
        """
        data_file = mockwiredata.DATA_FILE_VM_SETTINGS.copy()

        with mock_wire_protocol(data_file) as protocol:
            timestamp = datetime.datetime.utcnow()
            incarnation = '111'
            etag = '111111'
            protocol.mock_wire_data.set_incarnation(incarnation, timestamp=timestamp)
            protocol.mock_wire_data.set_etag(etag, timestamp=timestamp)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.Fabric)

            # Do a few checks on the mock data to ensure we catch changes in internal implementations
            # that may invalidate this setup.
            vm_settings, _ = protocol.client.get_host_plugin().fetch_vm_settings()
            if vm_settings.etag != etag:
                raise Exception("The HostGAPlugin is no in sync. Expected ETag {0}. Got {1}".format(etag, vm_settings.etag))
            if vm_settings.source != GoalStateSource.Fabric:
                raise Exception("The HostGAPlugin should be returning a Fabric goal state. Got {0}".format(vm_settings.source))

            goal_state = GoalState(protocol.client)
            if goal_state.incarnation != incarnation:
                raise Exception("The WireServer is no in sync. Expected incarnation {0}. Got {1}".format(incarnation, goal_state.incarnation))

            if goal_state.extensions_goal_state.correlation_id != vm_settings.correlation_id:
                raise Exception(
                    "The correlation ID in the WireServer and HostGAPlugin are not in sync. WS: {0} HGAP: {1}".format(
                        goal_state.extensions_goal_state.correlation_id, vm_settings.correlation_id))

            yield protocol

    def _assert_goal_state(self, goal_state, goal_state_id, channel=None, source=None):
        self.assertIn(goal_state_id, goal_state.extensions_goal_state.id, "Incorrect Goal State ID")
        if channel is not None:
            self.assertEqual(channel, goal_state.extensions_goal_state.channel, "Incorrect Goal State channel")
        if source is not None:
            self.assertEqual(source, goal_state.extensions_goal_state.source, "Incorrect Goal State source")


    def test_it_should_ignore_fabric_goal_states_from_the_host_ga_plugin(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            #
            # Verify __init__()
            #
            expected_incarnation = '111'  # test setup initializes to this value
            timestamp = datetime.datetime.utcnow() + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag('22222', timestamp)

            goal_state = GoalState(protocol.client)

            self._assert_goal_state(goal_state, expected_incarnation, channel=GoalStateChannel.WireServer)

            #
            # Verify update()
            #
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag('333333', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, expected_incarnation, channel=GoalStateChannel.WireServer)

    def test_it_should_use_fast_track_goal_states_from_the_host_ga_plugin(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.FastTrack)

            #
            # Verify __init__()
            #
            expected_etag = '22222'
            timestamp = datetime.datetime.utcnow() + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag(expected_etag, timestamp)

            goal_state = GoalState(protocol.client)

            self._assert_goal_state(goal_state, expected_etag, channel=GoalStateChannel.HostGAPlugin)

            #
            # Verify update()
            #
            expected_etag = '333333'
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag(expected_etag, timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, expected_etag, channel=GoalStateChannel.HostGAPlugin)

    def test_it_should_use_the_most_recent_goal_state(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            goal_state = GoalState(protocol.client)

            # The most recent goal state is FastTrack
            timestamp = datetime.datetime.utcnow() + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.FastTrack)
            protocol.mock_wire_data.set_etag('222222', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222222', channel=GoalStateChannel.HostGAPlugin, source=GoalStateSource.FastTrack)

            # The most recent goal state is Fabric
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_incarnation('222', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222', channel=GoalStateChannel.WireServer, source=GoalStateSource.Fabric)

            # The most recent goal state is Fabric, but it is coming from the HostGAPlugin (should be ignored)
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.Fabric)
            protocol.mock_wire_data.set_etag('333333', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222', channel=GoalStateChannel.WireServer, source=GoalStateSource.Fabric)
