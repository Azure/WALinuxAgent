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

from tests_e2e.orchestrator.lib.agent_test_suite import AgentTestSuite
from tests_e2e.scenarios.tests.bvts.extension_operations import ExtensionOperationsBvt
from tests_e2e.scenarios.tests.bvts.vm_access import VmAccessBvt
from tests_e2e.scenarios.tests.bvts.run_command import RunCommandBvt

# E0401: Unable to import 'lisa' (import-error)
from lisa import (  # pylint: disable=E0401
    Node,
    TestCaseMetadata,
    TestSuiteMetadata,
)


@TestSuiteMetadata(area="bvt", category="", description="Test suite for Agent BVTs")
class AgentBvt(AgentTestSuite):
    """
    Test suite for Agent BVTs
    """
    @TestCaseMetadata(description="", priority=0)
    def main(self, node: Node) -> None:
        self.execute(
            node,
            [
                ExtensionOperationsBvt,  # Tests the basic operations (install, enable, update, uninstall) using CustomScript
                RunCommandBvt,
                VmAccessBvt
            ]
        )



