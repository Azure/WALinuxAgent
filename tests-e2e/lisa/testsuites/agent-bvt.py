from assertpy import assert_that
from pathlib import Path
from tests.agent_bvt import custom_script

from lisa import (
    CustomScriptBuilder,
    Logger,
    Node,
    simple_requirement,
    TestCaseMetadata,
    TestSuite,
    TestSuiteMetadata,
)
from lisa.sut_orchestrator.azure.common import get_node_context


@TestSuiteMetadata(
    area="bvt",
    category="functional",
    description="""
    A POC test suite for the waagent BVTs.
    """,
    requirement=simple_requirement(unsupported_os=[]),
)
class AgentBvt(TestSuite):
    @TestCaseMetadata(description="", priority=0)
    def check_agent_version(self, node: Node, log: Logger) -> None:
        script_path = CustomScriptBuilder(Path(__file__).parent.parent.joinpath("tests", "agent_bvt"), ["check_agent_version.py"])
        script = node.tools[script_path]
        result = script.run()
        log.info(result.stdout)
        log.error(result.stderr)
        assert_that(result.exit_code).is_equal_to(0)

    @TestCaseMetadata(description="", priority=0)
    def custom_script(self, node: Node) -> None:
        node_context = get_node_context(node)
        subscription_id = node.features._platform.subscription_id
        resource_group_name = node_context.resource_group_name
        vm_name = node_context.vm_name
        custom_script.main(subscription_id, resource_group_name, vm_name)
