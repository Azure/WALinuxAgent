from typing import List, Dict, Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class AgentCPUQuota(AgentVmTest):
    """
    The test verify that the agent detects when it is throttled for using too much CPU, that it detects processes that do belong to the agent's cgroup, and that resource metrics are generated.
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("=====Validating agent cpu quota checks")
        self._run_remote_test(self._ssh_client, "agent_cpu_quota-check_agent_cpu_quota.py", use_sudo=True)
        log.info("Successfully Verified that agent running in expected CPU quotas")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # This is produced by the test, so it is expected
            # Examples:
            #     2023-10-03T17:59:03.007572Z INFO MonitorHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Check on cgroups failed:
            #     [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 3190] /usr/bin/python3\x00/home/azureuser/bin/agent_cpu_quota-start_servi', '[PID: 3293] dd\x00if=/dev/zero\x00of=/dev/null\x00']
            #     [CGroupsException] The agent has been throttled for 5.7720997 seconds
            {'message': r"Disabling resource usage monitoring. Reason: Check on cgroups failed"},
            # This may happen during service stop while terminating the process
            # Example:
            #     2022-03-11T21:11:11.713161Z ERROR E2ETest [Errno 3] No such process:
            {'message': r'E2ETest.*No such process'},
            #     2022-10-26T15:38:39.655677Z ERROR E2ETest 'dd if=/dev/zero of=/dev/null' failed: -15 ():
            {'message': r"E2ETest.*dd.*failed: -15"}
        ]
        return ignore_rules


if __name__ == "__main__":
    AgentCPUQuota.run_from_command_line()
