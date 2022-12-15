from tests_e2e.orchestrator.lib.agent_test_suite import AgentTestSuite
from tests_e2e.scenarios.tests.bvts import custom_script

# E0401: Unable to import 'lisa' (import-error)
from lisa import (  # pylint: disable=E0401
    TestCaseMetadata,
    TestSuiteMetadata,
)


@TestSuiteMetadata(
    area="bvt",
    category="functional",
    description="""
    A POC test suite for the waagent BVTs.
    """,
)
class AgentBvt(AgentTestSuite):
    @TestCaseMetadata(description="", priority=0)
    def main(self, *_, **__) -> None:
        self.custom_script()

    def custom_script(self) -> None:
        custom_script.main(self._subscription_id, self._resource_group_name, self._vm_name)


