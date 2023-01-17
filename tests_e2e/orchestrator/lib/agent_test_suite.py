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
import logging
import re

from assertpy import fail
from pathlib import Path
from threading import current_thread, RLock
from typing import List, Type

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     E0401: Unable to import 'lisa.sut_orchestrator' (import-error)
#     E0401: Unable to import 'lisa.sut_orchestrator.azure.common' (import-error)
from lisa import (  # pylint: disable=E0401
    CustomScriptBuilder,
    Logger,
    Node,
    TestSuite,
    TestSuiteMetadata
)
from lisa.sut_orchestrator import AZURE  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context, AzureNodeSchema  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.scenarios.lib.agent_test import AgentTest
from tests_e2e.scenarios.lib.agent_test_context import AgentTestContext
from tests_e2e.scenarios.lib.identifiers import VmIdentifier
from tests_e2e.scenarios.lib.logging import log as agent_test_logger  # Logger used by the tests


def _initialize_lisa_logger():
    """
    Customizes the LISA logger.

    The default behavior of this logger is too verbose, which makes reading the logs difficult. We set up a more succinct
    formatter and decrease the log level to INFO (the default is VERBOSE). In the future we may consider making this
    customization settable at runtime in case we need to debug LISA issues.
    """
    logger: Logger = logging.getLogger("lisa")

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s.%(msecs)03d [%(levelname)s] [%(threadName)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%SZ")
    for handler in logger.handlers:
        handler.setFormatter(formatter)


#
# We want to customize the LISA logger as early as possible, so we do it when this module is first imported. That will
# happen early in the LISA workflow, when it loads the test suites to execute.
#
_initialize_lisa_logger()


class AgentTestSuite(TestSuite):
    """
    Base class for Agent test suites. It provides facilities for setup, execution of tests and reporting results. Derived
    classes use the execute() method to run the tests in their corresponding suites.
    """

    class _Context(AgentTestContext):
        def __init__(self, vm: VmIdentifier, paths: AgentTestContext.Paths, connection: AgentTestContext.Connection):
            super().__init__(vm=vm, paths=paths, connection=connection)
            # These are initialized by AgentTestSuite._set_context().
            self.log: Logger = None
            self.node: Node = None
            self.runbook_name: str = None
            self.suite_name: str = None

    def __init__(self, metadata: TestSuiteMetadata) -> None:
        super().__init__(metadata)
        # The context is initialized by _set_context() via the call to execute()
        self.__context: AgentTestSuite._Context = None

    def _set_context(self, node: Node, log: Logger):
        connection_info = node.connection_info
        node_context = get_node_context(node)
        runbook = node.capability.get_extended_runbook(AzureNodeSchema, AZURE)
        # Remove the resource group and node suffix, e.g. "e1-n0" in "lisa-20230110-162242-963-e1-n0"
        runbook_name = re.sub(r"-\w+-\w+$", "", runbook.name)

        self.__context = AgentTestSuite._Context(
            vm=VmIdentifier(
                location=runbook.location,
                subscription=node.features._platform.subscription_id,
                resource_group=node_context.resource_group_name,
                name=node_context.vm_name),
            paths=AgentTestContext.Paths(
                # The runbook name is unique on each run, so we will use different working directory every time
                working_directory=Path().home()/"tmp"/runbook_name,
                remote_working_directory=Path('/home')/connection_info['username']),
            connection=AgentTestContext.Connection(
                ip_address=connection_info['address'],
                username=connection_info['username'],
                private_key_file=connection_info['private_key_file'],
                ssh_port=connection_info['port']))

        self.__context.log = log
        self.__context.node = node
        self.__context.suite_name = f"{self._metadata.full_name}_{runbook.marketplace.offer}-{runbook.marketplace.sku}"

    @property
    def context(self):
        if self.__context is None:
            raise Exception("The context for the AgentTestSuite has not been initialized")
        return self.__context

    @property
    def _log(self) -> Logger:
        return self.context.log

    #
    # Test suites within the same runbook may be executed concurrently, and setup needs to be done only once.
    # We use this lock to allow only 1 thread to do the setup. Setup completion is marked using the 'completed'
    # file: the thread doing the setup creates the file and threads that find that the file already exists
    # simply skip setup.
    #
    _setup_lock = RLock()

    def _setup(self) -> None:
        """
        Prepares the test suite for execution (currently, it just builds the agent package)

        Returns the path to the agent package.
        """
        AgentTestSuite._setup_lock.acquire()

        try:
            self._log.info("")
            self._log.info("**************************************** [Build] ****************************************")
            self._log.info("")
            completed: Path = self.context.working_directory/"completed"

            if completed.exists():
                self._log.info("Found %s. Build has already been done, skipping", completed)
                return

            self._log.info("Creating working directory: %s", self.context.working_directory)
            self.context.working_directory.mkdir(parents=True)
            self._build_agent_package()

            self._log.info("Completed setup, creating %s", completed)
            completed.touch()

        finally:
            AgentTestSuite._setup_lock.release()

    def _build_agent_package(self) -> None:
        """
        Builds the agent package and returns the path to the package.
        """
        self._log.info("Building agent package to %s", self.context.working_directory)

        makepkg.run(agent_family="Test", output_directory=str(self.context.working_directory), log=self._log)

        package_path: Path = self._get_agent_package_path()
        if not package_path.exists():
            raise Exception(f"Can't find the agent package at {package_path}")

        self._log.info("Built agent package as %s", package_path)

    def _get_agent_package_path(self) -> Path:
        """
        Returns the path to the agent package.
        """
        return self.context.working_directory/"eggs"/f"WALinuxAgent-{AGENT_VERSION}.zip"

    def _clean_up(self) -> None:
        """
        Cleans up any leftovers from the test suite run. Currently just an empty placeholder for future use.
        """

    def _setup_node(self) -> None:
        """
        Prepares the remote node for executing the test suite.
        """
        self._log.info("")
        self._log.info("************************************** [Node Setup] **************************************")
        self._log.info("")
        self._log.info("Test Node: %s", self.context.vm.name)
        self._log.info("Resource Group: %s", self.context.vm.resource_group)
        self._log.info("")

        self._install_agent_on_node()

    def _install_agent_on_node(self) -> None:
        """
        Installs the given agent package on the test node.
        """
        agent_package_path: Path = self._get_agent_package_path()

        # The install script needs to unzip the agent package; ensure unzip is installed on the test node
        self._log.info("Installing unzip tool on %s", self.context.node.name)
        self.context.node.os.install_packages("unzip")

        self._log.info("Installing %s on %s", agent_package_path, self.context.node.name)
        agent_package_remote_path = self.context.remote_working_directory/agent_package_path.name
        self._log.info("Copying %s to %s:%s", agent_package_path, self.context.node.name, agent_package_remote_path)
        self.context.node.shell.copy(agent_package_path, agent_package_remote_path)
        self.execute_script_on_node(
            self.context.test_source_directory/"orchestrator"/"scripts"/"install-agent",
            parameters=f"--package {agent_package_remote_path} --version {AGENT_VERSION}",
            sudo=True)

        self._log.info("The agent was installed successfully.")

    def _collect_node_logs(self) -> None:
        """
        Collects the test logs from the remote machine and copies them to the local machine
        """
        try:
            # Collect the logs on the test machine into a compressed tarball
            self._log.info("Collecting logs on test machine [%s]...", self.context.node.name)
            self.execute_script_on_node(self.context.test_source_directory/"orchestrator"/"scripts"/"collect-logs", sudo=True)

            # Copy the tarball to the local logs directory
            remote_path = "/tmp/waagent-logs.tgz"
            local_path = Path.home()/'logs'/'{0}.tgz'.format(self.context.suite_name)
            self._log.info("Copying %s:%s to %s", self.context.node.name, remote_path, local_path)
            self.context.node.shell.copy_back(remote_path, local_path)
        except:  # pylint: disable=bare-except
            self._log.exception("Failed to collect logs from the test machine")

    def execute(self, node: Node, log: Logger, test_suite: List[Type[AgentTest]]) -> None:
        """
        Executes each of the AgentTests in the given List. Note that 'test_suite' is a list of test classes, rather than
        instances of the test class (this method will instantiate each of these test classes).
        """
        self._set_context(node, log)

        failed: List[str] = []  # List of failed tests (names only)

        # The thread name is added to self._log, set it to the current test suite while we execute it
        thread_name = current_thread().name
        current_thread().name = self.context.suite_name

        # We create a separate log file for the test suite.
        # Make self._log write to this file as well, and set this file as the log for 'agent_test_logger',
        # which is the logger used by the tests.
        suite_log_file: Path = Path.home()/'logs'/f"{self.context.suite_name}.log"

        suite_log_handler = logging.FileHandler(str(suite_log_file))
        suite_log_handler.setFormatter(agent_test_logger.create_formatter())
        self._log.addHandler(suite_log_handler)

        agent_test_logger.set_current_thread_log(suite_log_file)

        try:
            self._setup()

            try:
                self._setup_node()

                self._log.info("")
                self._log.info("**************************************** %s ****************************************", self.context.suite_name)
                self._log.info("")

                results: List[str] = []

                for test in test_suite:
                    result: str = "[UNKNOWN]"
                    test_full_name = f"{self.context.suite_name} {test.__name__}"
                    self._log.info("******** Executing %s", test_full_name)
                    self._log.info("******** Executing %s", test_full_name)
                    self._log.info("")

                    try:
                        test(self.context).run()
                        result = f"[Passed] {test_full_name}"
                    except AssertionError as e:
                        failed.append(test.__name__)
                        result = f"[Failed] {test_full_name}"
                        self._log.error("%s", e)
                        agent_test_logger.error("%s", e)
                    except:  # pylint: disable=bare-except
                        failed.append(test.__name__)
                        result = f"[Error] {test_full_name}"
                        self._log.exception("UNHANDLED EXCEPTION")
                        agent_test_logger.exception("UNHANDLED EXCEPTION")

                    self._log.info("******** %s", result)
                    self._log.info("******** %s", result)
                    self._log.info("")
                    results.append(result)

                self._log.info("")
                self._log.info("********* [Test Results]")
                self._log.info("")
                for r in results:
                    self._log.info("\t%s", r)
                self._log.info("")

            finally:
                self._collect_node_logs()

        except:   # pylint: disable=bare-except
            # Log the error here so the it is decorated with the thread name, then re-raise
            self._log.exception("Unhandled exception in test suite")
            raise

        finally:
            self._clean_up()
            agent_test_logger.close_current_thread_log()
            self._log.removeHandler(suite_log_handler)
            current_thread().name = thread_name

        # Fail the entire test suite if any test failed; this exception is handled by LISA
        if len(failed) > 0:
            fail(f"{[self.context.suite_name]} One or more tests failed: {failed}")

    def execute_script_on_node(self, script_path: Path, parameters: str = "", sudo: bool = False) -> int:
        """
        Executes the given script on the test node; if 'sudo' is True, the script is executed using the sudo command.
        """
        custom_script_builder = CustomScriptBuilder(script_path.parent, [script_path.name])
        custom_script = self.context.node.tools[custom_script_builder]

        if parameters == '':
            command_line = f"{script_path}"
        else:
            command_line = f"{script_path} {parameters}"

        self._log.info("Executing [%s]", command_line)

        result = custom_script.run(parameters=parameters, sudo=sudo)

        if result.stdout != "":
            separator = "\n" if "\n" in result.stdout else " "
            self._log.info("stdout:%s%s", separator, result.stdout)
        if result.stderr != "":
            separator = "\n" if "\n" in result.stderr else " "
            self._log.error("stderr:%s%s", separator, result.stderr)

        if result.exit_code != 0:
            raise Exception(f"[{command_line}] failed. Exit code: {result.exit_code}")

        return result.exit_code


