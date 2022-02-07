# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import glob
import os
import re

from azurelinuxagent.common.protocol.goal_state import GoalState, _GET_GOAL_STATE_MAX_ATTEMPTS
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.utils.archive import ARCHIVE_DIRECTORY_NAME
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.tools import AgentTestCase, patch


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
    def test_fetch_full_goal_state_should_save_goal_state_to_history_directory(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            # use a new goal state with a specific test incarnation and etag
            protocol.mock_wire_data.set_incarnation(999)
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)

            matches = glob.glob(os.path.join(self.tmp_dir, ARCHIVE_DIRECTORY_NAME, "*_999"))
            self.assertTrue(len(matches) == 1, "Expected one history directory for incarnation 999. Got: {0}".format(matches))

            history_directory = matches[0]
            extensions_config_file = os.path.join(history_directory, "ExtensionsConfig.xml")
            expected_files = [
                os.path.join(history_directory, "GoalState.xml"),
                os.path.join(history_directory, "SharedConfig.xml"),
                os.path.join(history_directory, "HostingEnvironmentConfig.xml"),
                extensions_config_file,
            ]

            matches = glob.glob(os.path.join(self.tmp_dir, ARCHIVE_DIRECTORY_NAME, "*_888"))
            self.assertTrue(len(matches) == 1, "Expected one history directory for etag 888. Got: {0}".format(matches))

            history_directory = matches[0]
            vm_settings_file = os.path.join(history_directory, "VmSettings.json")
            expected_files.append(vm_settings_file)

            for f in expected_files:
                self.assertTrue(os.path.exists(f), "{0} was not saved".format(f))

            extensions_goal_state = goal_state.extensions_goal_state
            protected_settings = []
            for ext_handler in extensions_goal_state.extensions:
                for extension in ext_handler.settings:
                    if extension.protectedSettings is not None:
                        protected_settings.append(extension.protectedSettings)
            if len(protected_settings) == 0:
                raise Exception("The test goal state does not include any protected settings")

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



