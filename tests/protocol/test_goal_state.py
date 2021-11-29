# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

from azurelinuxagent.common.exception import IncompleteGoalStateError
from azurelinuxagent.common.protocol.goal_state import GoalState, _NUM_GS_FETCH_RETRIES
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
                with self.assertRaises(IncompleteGoalStateError):
                    GoalState(protocol.client)
                self.assertEqual(_NUM_GS_FETCH_RETRIES, mock_sleep.call_count, "Unexpected number of retries")

