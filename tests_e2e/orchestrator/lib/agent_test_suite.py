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
import contextlib
import datetime
import logging
import re
import traceback
import uuid

from enum import Enum
from pathlib import Path
from threading import current_thread, RLock
from typing import Any, Dict, List

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import (  # pylint: disable=E0401
    CustomScriptBuilder,
    Logger,
    Node,
    notifier,
    TestCaseMetadata,
    TestSuite,
    TestSuiteMetadata,
)
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401
from lisa.sut_orchestrator import AZURE  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context, AzureNodeSchema  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader, TestSuiteDescription
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log as agent_test_logger  # Logger used by the tests
from tests_e2e.tests.lib.logging import set_current_thread_log


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


#
# Helper to change the current thread name temporarily
#
@contextlib.contextmanager
def _set_thread_name(name: str):
    initial_name = current_thread().name
    current_thread().name = name
    try:
        yield
    finally:
        current_thread().name = initial_name


#
# Possible values for the collect_logs parameter
#
class CollectLogs(Enum):
    Always = 'always'   # Always collect logs
    Failed = 'failed'   # Collect logs only on test failures
    No = 'no'           # Never collect logs


@TestSuiteMetadata(area="waagent", category="", description="")
class AgentTestSuite(TestSuite):
    """
    Manages the setup of test VMs and execution of Agent test suites. This class acts as the interface with the LISA framework, which
    will invoke the execute() method when a runbook is executed.
    """

    class _Context(AgentTestContext):
        def __init__(self, vm: VmIdentifier, paths: AgentTestContext.Paths, connection: AgentTestContext.Connection):
            super().__init__(vm=vm, paths=paths, connection=connection)
            # These are initialized by AgentTestSuite._set_context().
            self.log: Logger = None
            self.node: Node = None
            self.runbook_name: str = None
            self.image_name: str = None
            self.test_suites: List[str] = None
            self.collect_logs: str = None
            self.skip_setup: bool = None

    def __init__(self, metadata: TestSuiteMetadata) -> None:
        super().__init__(metadata)
        # The context is initialized by _set_context() via the call to execute()
        self.__context: AgentTestSuite._Context = None

    def _set_context(self, node: Node, variables: Dict[str, Any], log: Logger):
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
        self.__context.image_name = f"{runbook.marketplace.offer}-{runbook.marketplace.sku}"
        self.__context.test_suites = AgentTestSuite._get_required_parameter(variables, "test_suites")
        self.__context.collect_logs = AgentTestSuite._get_required_parameter(variables, "collect_logs")
        self.__context.skip_setup = AgentTestSuite._get_required_parameter(variables, "skip_setup")

        self._log.info(
            "Test suite parameters: [skip_setup: %s] [collect_logs: %s] [test_suites: %s]",
            self.context.skip_setup,
            self.context.collect_logs,
            self.context.test_suites)

    @staticmethod
    def _get_required_parameter(variables: Dict[str, Any], name: str) -> Any:
        value = variables.get(name)
        if value is None:
            raise Exception(f"The runbook is missing required parameter '{name}'")
        return value

    @property
    def context(self):
        if self.__context is None:
            raise Exception("The context for the AgentTestSuite has not been initialized")
        return self.__context

    @property
    def _log(self) -> Logger:
        """
        Returns a reference to the LISA Logger.
        """
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
            local_path = Path.home()/'logs'/'{0}.tgz'.format(self.context.image_name)
            self._log.info("Copying %s:%s to %s", self.context.node.name, remote_path, local_path)
            self.context.node.shell.copy_back(remote_path, local_path)
        except:  # pylint: disable=bare-except
            self._log.exception("Failed to collect logs from the test machine")

    @TestCaseMetadata(description="", priority=0)
    def execute(self, node: Node, variables: Dict[str, Any], log: Logger) -> None:
        """
        Executes each of the AgentTests in the given List. Note that 'test_suite' is a list of test classes, rather than
        instances of the test class (this method will instantiate each of these test classes).
        """
        self._set_context(node, variables, log)

        test_suite_success = True

        with _set_thread_name(self.context.image_name):  # The thread name is added to self._log
            try:
                if not self.context.skip_setup:
                    self._setup()

                try:
                    if not self.context.skip_setup:
                        self._setup_node()

                    test_suites: List[TestSuiteDescription] = AgentTestLoader(self.context.test_source_directory).load(self.context.test_suites)

                    for suite in test_suites:
                        test_suite_success = self._execute_test_suite(suite) and test_suite_success

                finally:
                    collect = self.context.collect_logs
                    if collect == CollectLogs.Always or collect == CollectLogs.Failed and not test_suite_success:
                        self._collect_node_logs()

            except:   # pylint: disable=bare-except
                # Note that we report the error to the LISA log and then re-raise it. We log it here
                # so that the message is decorated with the thread name in the LISA log; we re-raise
                # to let LISA know the test errored out (LISA will report that error one more time
                # in its log)
                self._log.exception("UNHANDLED EXCEPTION")
                raise

            finally:
                self._clean_up()

    def _execute_test_suite(self, suite: TestSuiteDescription) -> bool:
        """
        Executes the given test suite and returns True if all the tests in the suite succeeded.
        """
        suite_name = suite.name
        suite_full_name = f"{suite_name}-{self.context.image_name}"

        with _set_thread_name(suite_full_name):  # The thread name is added to self._log
            with set_current_thread_log(Path.home()/'logs'/f"{suite_full_name}.log"):
                start_time: datetime.datetime = datetime.datetime.now()

                message: TestResultMessage = TestResultMessage()
                message.type = "AgentTestResultMessage"
                message.id_ = str(uuid.uuid4())
                message.status = TestStatus.RUNNING
                message.suite_full_name = suite_name
                message.suite_name = message.suite_full_name
                message.full_name = f"{suite_name}-{self.context.image_name}"
                message.name = message.full_name
                message.elapsed = 0
                notifier.notify(message)

                try:
                    agent_test_logger.info("")
                    agent_test_logger.info("**************************************** %s ****************************************", suite_name)
                    agent_test_logger.info("")

                    failed: List[str] = []
                    summary: List[str] = []

                    for test in suite.tests:
                        test_name = test.__name__
                        test_full_name = f"{suite_name}-{test_name}"

                        agent_test_logger.info("******** Executing %s", test_name)
                        self._log.info("******** Executing %s", test_full_name)

                        try:

                            test(self.context).run()

                            summary.append(f"[Passed] {test_name}")
                            agent_test_logger.info("******** [Passed] %s", test_name)
                            self._log.info("******** [Passed] %s", test_full_name)
                        except AssertionError as e:
                            summary.append(f"[Failed] {test_name}")
                            failed.append(test_name)
                            agent_test_logger.error("******** [Failed] %s: %s", test_name, e)
                            self._log.error("******** [Failed] %s", test_full_name)
                        except:  # pylint: disable=bare-except
                            summary.append(f"[Error] {test_name}")
                            failed.append(test_name)
                            agent_test_logger.exception("UNHANDLED EXCEPTION IN %s", test_name)
                            self._log.exception("UNHANDLED EXCEPTION IN %s", test_full_name)

                        agent_test_logger.info("")

                    agent_test_logger.info("********* [Test Results]")
                    agent_test_logger.info("")
                    for r in summary:
                        agent_test_logger.info("\t%s", r)
                    agent_test_logger.info("")

                    if len(failed) == 0:
                        message.status = TestStatus.PASSED
                    else:
                        message.status = TestStatus.FAILED
                        message.message = f"Tests failed: {failed}"

                except:  # pylint: disable=bare-except
                    message.status = TestStatus.FAILED
                    message.message = "Unhandled exception while executing test suite."
                    message.stacktrace = traceback.format_exc()
                finally:
                    message.elapsed = (datetime.datetime.now() - start_time).total_seconds()
                    notifier.notify(message)

                return len(failed) == 0

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


