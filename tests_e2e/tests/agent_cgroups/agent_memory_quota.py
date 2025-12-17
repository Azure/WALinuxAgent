from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class AgentMemoryQuota(AgentVmTest):
    """
    The test verify that the agent detects when it is throttled for using too much Memory, that it detects processes that do belong to the agent's cgroup, and that resource metrics are generated.
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("=====Validating agent memory quota checks")
        self._run_remote_test(self._ssh_client, "agent_memory_quota-check_agent_memory_quota.py", use_sudo=True)
        log.info("Successfully Verified that agent running in expected Memory quotas")


if __name__ == "__main__":
    AgentMemoryQuota.run_from_command_line()
