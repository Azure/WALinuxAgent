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

from pathlib import Path
import shutil

import makepkg

from lisa import (
    CustomScriptBuilder,
    Logger,
    Node,
    TestSuite,
    TestSuiteMetadata,
)
from lisa.sut_orchestrator.azure.common import get_node_context

from azurelinuxagent.common.version import AGENT_VERSION


class AgentTestSuite(TestSuite):
    """
    Base class for VM Agent tests. It provides initialization, cleanup, and common utilities for all of the VM Agent test suites.
    """
    def __init__(self, metadata: TestSuiteMetadata):
        super().__init__(metadata)
        # The actual initialization happens in _initialize()
        self._log = None
        self._node = None
        self._test_source_directory = None
        self._subscription_id = None
        self._resource_group_name = None
        self._vm_name = None

    def before_case(self, *_, **kwargs) -> None:
        self._initialize(kwargs['node'], kwargs['log'])
        self._setup_node()

    def after_case(self, *_, **__) -> None:
        try:
            self._collect_node_logs()
        finally:
            self._clean_up()

    def _initialize(self, node: Node, log: Logger) -> None:
        self._node = node
        self._log = log

        node_context = get_node_context(node)
        self._subscription_id = node.features._platform.subscription_id
        self._resource_group_name = node_context.resource_group_name
        self._vm_name = node_context.vm_name

        self._test_source_directory = AgentTestSuite._get_test_source_directory()
        self._working_directory = Path().home()/"waagent-tmp"
        self._node_home_directory = Path('/home')/self._node.connection_info['username']

        self._log.info(f"Test Node: {self._vm_name}")
        self._log.info(f"Resource Group: {self._resource_group_name}")
        self._log.info(f"Working directory: {self._working_directory}...")

        if self._working_directory.exists():
            self._log.info(f"Removing existing working directory: {self._working_directory}...")
            try:
                shutil.rmtree(self._working_directory.as_posix())
            except Exception as exception:
                self._log.warning(f"Failed to remove the working directory: {exception}")
        self._working_directory.mkdir()

    def _clean_up(self) -> None:
        self._log.info(f"Removing {self._working_directory}...")
        shutil.rmtree(self._working_directory.as_posix(), ignore_errors=True)

    @staticmethod
    def _get_test_source_directory() -> Path:
        """
        Returns the root directory of the source code for the end-to-end tests (".../WALinuxAgent/tests_e2e")
        """
        path = Path(__file__)
        while path.name != '':
            if path.name == "tests_e2e":
                return path
            path = path.parent
        raise Exception("Can't find the test root directory (tests_e2e)")

    def _setup_node(self) -> None:
        """
        Prepares the remote node for executing the test suite.
        """
        agent_package_path = self._build_agent_package()
        self._install_agent_on_node(agent_package_path)

    def _build_agent_package(self) -> Path:
        """
        Builds the agent package and returns the path to the package.
        """
        build_path = self._working_directory/"build"

        # The same orchestrator machine may be executing multiple suites on the same test VM, or
        # the same suite on one or more test VMs; we use this file to mark the build is already done
        build_done_path = self._working_directory/"build.done"
        if build_done_path.exists():
            self._log.info(f"The agent build is already completed, will use existing package.")
        else:
            self._log.info(f"Building agent package to {build_path}")
            makepkg.run(agent_family="Test", output_directory=str(build_path), log=self._log)
            build_done_path.touch()

        package_path = build_path/"eggs"/f"WALinuxAgent-{AGENT_VERSION}.zip"
        if not package_path.exists():
            raise Exception(f"Can't find the agent package at {package_path}")

        self._log.info(f"Agent package: {package_path}")

        return package_path

    def _install_agent_on_node(self, agent_package: Path) -> None:
        """
        Installs the given agent package on the test node.
        """
        # The same orchestrator machine may be executing multiple suites on the same test VM,
        # we use this file to mark the agent is already installed on the test VM.
        install_done_path = self._working_directory/f"agent-install.{self._vm_name}.done"
        if install_done_path.exists():
            self._log.info(f"Package {agent_package} is already installed on {self._vm_name}...")
            return

        self._log.info(f"Installing {agent_package} on {self._vm_name}...")
        agent_package_remote_path = self._node_home_directory/agent_package.name
        self._node.shell.copy(agent_package, agent_package_remote_path)
        self._execute_script_on_node(
            self._test_source_directory/"orchestrator"/"scripts"/"install-agent",
            parameters=f"--package {agent_package_remote_path} --version {AGENT_VERSION}",
            sudo=True)

        self._log.info(f"The agent was installed successfully.")
        install_done_path.touch()

    def _collect_node_logs(self) -> None:
        """
        Collects the test logs from the remote machine and copied them to the local machine
        """
        # Collect the logs on the test machine into a compressed tarball
        self._log.info("Collecting logs on test machine [%s]...", self._node.name)
        self._execute_script_on_node(self._test_source_directory/"orchestrator"/"scripts"/"collect-logs", sudo=True)

        # Copy the tarball to the local logs directory
        remote_path = self._node_home_directory/"logs.tgz"
        local_path = Path.home()/'logs'/'vm-logs-{0}.tgz'.format(self._node.name)
        self._log.info(f"Copying {self._node.name}:{remote_path} to {local_path}")
        self._node.shell.copy_back(remote_path, local_path)

    def _execute_script_on_node(self, script_path: Path, parameters: str = "", sudo: bool = False) -> int:
        custom_script_builder = CustomScriptBuilder(script_path.parent, [script_path.name])
        custom_script = self._node.tools[custom_script_builder]

        self._log.info(f"Executing {script_path} {parameters}")
        result = custom_script.run(parameters=parameters, sudo=sudo)

        # # Currently LISA appends stderr to stdout so use info or warning depending on the exit code
        # if result.exit_code == 0:
        #     log = self._log.info
        # else:
        #     log = self._log.error
        #
        # if result.stdout != '':
        #     log(f"{result.stdout}")
        # if result.stderr != '':
        #     log(f"{result.stderr}")
        #
        return result.exit_code


