from assertpy import assert_that

from tests_e2e.scenarios.testsuites.agent_test_suite import AgentTestSuite
from tests_e2e.scenarios.tests.bvts import custom_script

from lisa import (
    simple_requirement,
    TestCaseMetadata,
    TestSuiteMetadata,
)


@TestSuiteMetadata(
    area="bvt",
    category="functional",
    description="""
    A POC test suite for the waagent BVTs.
    """,
    requirement=simple_requirement(unsupported_os=[]),
)
class AgentBvt(AgentTestSuite):
    @TestCaseMetadata(description="", priority=0)
    def main(self, *_, **__) -> None:
        self.check_agent_version()
        self.custom_script()

    def check_agent_version(self) -> None:
        exit_code = self._execute_remote_script(self._test_root.joinpath("scenarios", "tests"), "check_agent_version.py")
        assert_that(exit_code).is_equal_to(0)

    def custom_script(self) -> None:
        custom_script.main(self._subscription_id, self._resource_group_name, self._vm_name)


