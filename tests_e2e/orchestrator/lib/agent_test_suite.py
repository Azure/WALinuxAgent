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
from collections.abc import Callable
from pathlib import Path
from shutil import rmtree

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     E0401: Unable to import 'lisa.sut_orchestrator' (import-error)
#     E0401: Unable to import 'lisa.sut_orchestrator.azure.common' (import-error)
from lisa import (  # pylint: disable=E0401
    CustomScriptBuilder,
    Node
)
from lisa.sut_orchestrator import AZURE  # pylintd: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context, AzureNodeSchema  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.scenarios.lib.agent_test_context import AgentTestContext
from tests_e2e.scenarios.lib.identifiers import VmIdentifier
from tests_e2e.scenarios.lib.logging import log


class AgentTestScenario(object):
    """
    Instances of this class are used to execute Agent test scenarios. It also provides facilities to execute commands over SSH.
    """
    def __init__(self, node: Node) -> None:
        node_context = get_node_context(node)

        runbook = node.capability.get_extended_runbook(AzureNodeSchema, AZURE)

        self._node: Node = node
        self._context: AgentTestContext = AgentTestContext(
            VmIdentifier(
                location=runbook.location,
                subscription=node.features._platform.subscription_id,
                resource_group=node_context.resource_group_name,
                name=node_context.vm_name),
            remote_working_directory=Path('/home')/node.connection_info['username'])

    def _setup(self) -> None:
        """
        Prepares the test scenario for execution
        """
        log.info("Test Node: %s", self._context.vm.name)
        log.info("Resource Group: %s", self._context.vm.resource_group)
        log.info("Working directory: %s", self._context.working_directory)

        if self._context.working_directory.exists():
            log.info("Removing existing working directory: %s", self._context.working_directory)
            try:
                rmtree(self._context.working_directory.as_posix())
            except Exception as exception:
                log.warning("Failed to remove the working directory: %s", exception)
        self._context.working_directory.mkdir()

    def _clean_up(self) -> None:
        """
        Cleans up any leftovers from the test scenario run.
        """
        log.info("Removing %s", self._context.working_directory)
        rmtree(self._context.working_directory.as_posix(), ignore_errors=True)

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
        build_path = self._context.working_directory/"build"

        log.info("Building agent package to %s", build_path)

        makepkg.run(agent_family="Test", output_directory=str(build_path), log=log)

        package_path = build_path/"eggs"/f"WALinuxAgent-{AGENT_VERSION}.zip"
        if not package_path.exists():
            raise Exception(f"Can't find the agent package at {package_path}")

        log.info("Agent package: %s", package_path)

        return package_path

    def _install_agent_on_node(self, agent_package: Path) -> None:
        """
        Installs the given agent package on the test node.
        """
        # The install script needs to unzip the agent package; ensure unzip is installed on the test node
        log.info("Installing unzip tool on %s", self._node.name)
        self._node.os.install_packages("unzip")

        log.info("Installing %s on %s", agent_package, self._node.name)
        agent_package_remote_path = self._context.remote_working_directory / agent_package.name
        log.info("Copying %s to %s:%s", agent_package, self._node.name, agent_package_remote_path)
        self._node.shell.copy(agent_package, agent_package_remote_path)
        self.execute_script_on_node(
            self._context.test_source_directory/"orchestrator"/"scripts"/"install-agent",
            parameters=f"--package {agent_package_remote_path} --version {AGENT_VERSION}",
            sudo=True)

        log.info("The agent was installed successfully.")

    def _collect_node_logs(self) -> None:
        """
        Collects the test logs from the remote machine and copies them to the local machine
        """
        try:
            # Collect the logs on the test machine into a compressed tarball
            log.info("Collecting logs on test machine [%s]...", self._node.name)
            self.execute_script_on_node(self._context.test_source_directory/"orchestrator"/"scripts"/"collect-logs", sudo=True)

            # Copy the tarball to the local logs directory
            remote_path = self._context.remote_working_directory / "logs.tgz"
            local_path = Path.home()/'logs'/'vm-logs-{0}.tgz'.format(self._node.name)
            log.info("Copying %s:%s to %s", self._node.name, remote_path, local_path)
            self._node.shell.copy_back(remote_path, local_path)
        except Exception as e:
            log.warning("Failed to collect logs from the test machine: %s", e)

    def execute(self, scenario: Callable[[AgentTestContext], None]) -> None:
        """
        Executes the given scenario
        """
        log.info("")
        log.info("**************************************** waagent ****************************************")
        log.info("")

        try:
            self._setup()
            try:
                self._setup_node()
                scenario(self._context)
            finally:
                self._collect_node_logs()
        finally:
            self._clean_up()
            log.info("")
            log.info("************************************ end waagent ************************************")
            log.info("")

    def execute_script_on_node(self, script_path: Path, parameters: str = "", sudo: bool = False) -> int:
        """
        Executes the given script on the test node; if 'sudo' is True, the script is executed using the sudo command.
        """
        custom_script_builder = CustomScriptBuilder(script_path.parent, [script_path.name])
        custom_script = self._node.tools[custom_script_builder]

        if parameters == '':
            command_line = f"{script_path}"
        else:
            command_line = f"{script_path} {parameters}"

        log.info("Executing [%s]", command_line)

        result = custom_script.run(parameters=parameters, sudo=sudo)

        if result.exit_code != 0:
            output = result.stdout if result.stderr == "" else f"{result.stdout}\n{result.stderr}"
            raise Exception(f"[{command_line}] failed:\n{output}")

        if result.stdout != "":
            separator = "\n" if "\n" in result.stdout else " "
            log.info("stdout:%s%s", separator, result.stdout)
        if result.stderr != "":
            separator = "\n" if "\n" in result.stderr else " "
            log.error("stderr:%s%s", separator, result.stderr)

        return result.exit_code


