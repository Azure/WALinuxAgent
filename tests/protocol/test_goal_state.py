# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

from azurelinuxagent.common.exception import IncompleteGoalStateError
from azurelinuxagent.common.protocol.goal_state import GoalState
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.protocol.mocks import HttpRequestPredicates
from tests.tools import AgentTestCase

class GoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    def test_incomplete_gs_should_fail(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            GoalState.fetch_full_goal_state(protocol.client)

            protocol.mock_wire_data.data_files = mockwiredata.DATA_FILE_NOOP_GS
            protocol.mock_wire_data.reload()
            protocol.mock_wire_data.set_incarnation(2)

            with self.assertRaises(IncompleteGoalStateError):
                GoalState.fetch_full_goal_state_if_incarnation_different_than(protocol.client, 1)

