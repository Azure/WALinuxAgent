# Microsoft Azure Linux Agent
#
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

from tests_e2e.orchestrator.lib.agent_test_suite import AgentTestScenario
from tests_e2e.scenarios.lib.agent_test_context import AgentTestContext
from tests_e2e.scenarios.tests.bvts import extension_operations

# E0401: Unable to import 'lisa' (import-error)
from lisa import (  # pylint: disable=E0401
    Node,
    TestCaseMetadata,
    TestSuite,
    TestSuiteMetadata,
)


@TestSuiteMetadata(area="bvt", category="", description="Test suite for Agent BVTs")
class AgentBvt(TestSuite):
    """
    Test suite for Agent BVTs
    """
    @TestCaseMetadata(description="", priority=0)
    def main(self, node: Node) -> None:
        def tests(ctx: AgentTestContext) -> None:
            extension_operations.main(ctx)

        AgentTestScenario(node).execute(tests)



