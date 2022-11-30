from pathlib import Path, PurePath

from lisa import (
    CustomScriptBuilder,
    TestSuite,
    TestSuiteMetadata,
)
from lisa.sut_orchestrator.azure.common import get_node_context


class AgentTestSuite(TestSuite):
    def __init__(self, metadata: TestSuiteMetadata):
        super().__init__(metadata)
        self._log = None
        self._node = None
        self._test_root = None
        self._subscription_id = None
        self._resource_group_name = None
        self._vm_name = None

    def before_case(self, *_, **kwargs) -> None:
        node = kwargs['node']
        log = kwargs['log']
        node_context = get_node_context(node)

        self._log = log
        self._node = node
        self._test_root = Path(__file__).parent.parent.parent
        self._subscription_id = node.features._platform.subscription_id
        self._resource_group_name = node_context.resource_group_name
        self._vm_name = node_context.vm_name

    def after_case(self, *_, **__) -> None:
        # Collect the logs on the test machine into a compressed tarball
        self._log.info("Collecting logs on test machine [%s]...", self._node.name)
        self._execute_remote_script(self._test_root.joinpath("scripts"), "collect_logs.sh")

        # Copy the tarball to the local logs directory
        remote_path = PurePath('/home') / self._node.connection_info['username'] / 'logs.tgz'
        local_path = Path.home() / 'logs' / 'vm-logs-{0}.tgz'.format(self._node.name)
        self._log.info("Copying %s:%s to %s...", self._node.name, remote_path, local_path)
        self._node.shell.copy_back(remote_path, local_path)

    def _execute_remote_script(self, path: Path, script: str) -> int:
        custom_script_builder = CustomScriptBuilder(path, [script])
        custom_script = self._node.tools[custom_script_builder]
        self._log.info('Executing %s/%s...', path, script)
        result = custom_script.run()
        if result.stdout:
            self._log.info('%s', result.stdout)
        if result.stderr:
            self._log.error('%s', result.stderr)
        return result.exit_code
