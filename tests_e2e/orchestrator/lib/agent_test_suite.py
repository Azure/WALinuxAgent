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

from pathlib import Path
from threading import current_thread, RLock
from typing import Any, Dict, List

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import (  # pylint: disable=E0401
    Logger,
    Node,
    notifier,
    TestCaseMetadata,
    TestSuite as LisaTestSuite,
    TestSuiteMetadata,
)
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401
from lisa.sut_orchestrator import AZURE  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context, AzureNodeSchema  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.orchestrator.lib.agent_test_loader import TestSuiteInfo
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log as agent_test_logger  # Logger used by the tests
from tests_e2e.tests.lib.logging import set_current_thread_log
from tests_e2e.tests.lib.shell import run_command
from tests_e2e.tests.lib.ssh_client import SshClient


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
class CollectLogs(object):
    Always = 'always'   # Always collect logs
    Failed = 'failed'   # Collect logs only on test failures
    No = 'no'           # Never collect logs


@TestSuiteMetadata(area="waagent", category="", description="")
class AgentTestSuite(LisaTestSuite):
    """
    Manages the setup of test VMs and execution of Agent test suites. This class acts as the interface with the LISA framework, which
    will invoke the execute() method when a runbook is executed.
    """

    class _Context(AgentTestContext):
        def __init__(self, vm: VmIdentifier, paths: AgentTestContext.Paths, connection: AgentTestContext.Connection):
            super().__init__(vm=vm, paths=paths, connection=connection)
            # These are initialized by AgentTestSuite._set_context().
            self.log_path: Path = None
            self.log: Logger = None
            self.node: Node = None
            self.runbook_name: str = None
            self.image_name: str = None
            self.is_vhd: bool = None
            self.test_suites: List[AgentTestSuite] = None
            self.collect_logs: str = None
            self.skip_setup: bool = None
            self.ssh_client: SshClient = None

    def __init__(self, metadata: TestSuiteMetadata) -> None:
        super().__init__(metadata)
        # The context is initialized by _set_context() via the call to execute()
        self.__context: AgentTestSuite._Context = None

    def _set_context(self, node: Node, variables: Dict[str, Any], lisa_log_path: str, log: Logger):
        connection_info = node.connection_info
        node_context = get_node_context(node)
        runbook = node.capability.get_extended_runbook(AzureNodeSchema, AZURE)
        # Remove the resource group and node suffix, e.g. "e1-n0" in "lisa-20230110-162242-963-e1-n0"
        runbook_name = re.sub(r"-\w+-\w+$", "", runbook.name)

        self.__context = self._Context(
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

        self.__context.log_path = self._get_log_path(variables, lisa_log_path)
        self.__context.log = log
        self.__context.node = node
        self.__context.is_vhd = self._get_optional_parameter(variables, "c_vhd") != ""
        self.__context.image_name = f"{node.os.name}-vhd" if self.__context.is_vhd else self._get_required_parameter(variables, "c_env_name")
        self.__context.test_suites = self._get_required_parameter(variables, "c_test_suites")
        self.__context.collect_logs = self._get_required_parameter(variables, "collect_logs")
        self.__context.skip_setup = self._get_required_parameter(variables, "skip_setup")
        self.__context.ssh_client = SshClient(ip_address=self.__context.vm_ip_address, username=self.__context.username, private_key_file=self.__context.private_key_file)

    @staticmethod
    def _get_required_parameter(variables: Dict[str, Any], name: str) -> Any:
        value = variables.get(name)
        if value is None:
            raise Exception(f"The runbook is missing required parameter '{name}'")
        return value

    @staticmethod
    def _get_optional_parameter(variables: Dict[str, Any], name: str, default_value: Any = "") -> Any:
        value = variables.get(name)
        if value is None:
            return default_value
        return value

    @staticmethod
    def _get_log_path(variables: Dict[str, Any], lisa_log_path: str):
        # NOTE: If "log_path" is not given as argument to the runbook, use a path derived from LISA's log for the test suite.
        # That path is derived from LISA's "--log_path" command line argument and has a value similar to
        # "<--log_path>/20230217/20230217-040022-342/tests/20230217-040119-288-agent_test_suite"; use the directory
        # 2 levels up.
        return Path(variables["log_path"]) if "log_path" in variables else Path(lisa_log_path).parent.parent

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
        self._setup_lock.acquire()

        try:
            self._log.info("")
            self._log.info("**************************************** [Build] ****************************************")
            self._log.info("")
            completed: Path = self.context.working_directory/"completed"

            if completed.exists():
                self._log.info("Found %s. Build has already been done, skipping.", completed)
                return

            self._log.info("Creating working directory: %s", self.context.working_directory)
            self.context.working_directory.mkdir(parents=True)
            self._build_agent_package()

            self._log.info("Completed setup, creating %s", completed)
            completed.touch()

        finally:
            self._setup_lock.release()

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

        self._install_tools_on_node()

        if self.context.is_vhd:
            self._log.info("Using a VHD; will not install the test Agent.")
        else:
            self._install_agent_on_node()

    def _install_tools_on_node(self) -> None:
        """
        Installs the test tools on the test node
        """
        self.context.ssh_client.run_command("mkdir -p ~/bin")

        tools_path = self.context.test_source_directory/"orchestrator"/"scripts"
        self._log.info(f"Copying {tools_path} to the test node")
        self.context.ssh_client.copy(tools_path, Path("~/bin"), remote_target=True, recursive=True)

        if self.context.ssh_client.get_architecture() == "aarch64":
            pypy_path = Path("/tmp/pypy3.7-arm64.tar.bz2")
            pypy_download = "https://downloads.python.org/pypy/pypy3.7-v7.3.5-aarch64.tar.bz2"
        else:
            pypy_path = Path("/tmp/pypy3.7-x64.tar.bz2")
            pypy_download = "https://downloads.python.org/pypy/pypy3.7-v7.3.5-linux64.tar.bz2"

        if not pypy_path.exists():
            self._log.info(f"Downloading {pypy_download} to {pypy_path}")
            run_command(["wget", pypy_download, "-O",  pypy_path])
        self._log.info(f"Copying {pypy_path} to the test node")
        self.context.ssh_client.copy(pypy_path, Path("~/bin/pypy3.7.tar.bz2"), remote_target=True)

        self._log.info(f'Installing tools on the test node\n{self.context.ssh_client.run_command("~/bin/scripts/install-tools")}')
        self._log.info(f'Remote commands will use {self.context.ssh_client.run_command("which python3")}')

    def _install_agent_on_node(self) -> None:
        """
        Installs the given agent package on the test node.
        """
        agent_package_path: Path = self._get_agent_package_path()

        self._log.info("Installing %s on %s", agent_package_path, self.context.node.name)
        agent_package_remote_path = self.context.remote_working_directory/agent_package_path.name
        self._log.info("Copying %s to %s:%s", agent_package_path, self.context.node.name, agent_package_remote_path)
        self.context.ssh_client.copy(agent_package_path, agent_package_remote_path, remote_target=True)
        stdout = self.context.ssh_client.run_command(f"install-agent --package {agent_package_remote_path} --version {AGENT_VERSION}", use_sudo=True)
        self._log.info(stdout)

        self._log.info("The agent was installed successfully.")

    def _collect_node_logs(self) -> None:
        """
        Collects the test logs from the remote machine and copies them to the local machine
        """
        try:
            # Collect the logs on the test machine into a compressed tarball
            self._log.info("Collecting logs on test machine [%s]...", self.context.node.name)
            stdout = self.context.ssh_client.run_command("collect-logs", use_sudo=True)
            self._log.info(stdout)

            # Copy the tarball to the local logs directory
            remote_path = "/tmp/waagent-logs.tgz"
            local_path = self.context.log_path/'{0}.tgz'.format(self.context.image_name)
            self._log.info("Copying %s:%s to %s", self.context.node.name, remote_path, local_path)
            self.context.ssh_client.copy(remote_path, local_path, remote_source=True)
        except:  # pylint: disable=bare-except
            self._log.exception("Failed to collect logs from the test machine")

    @TestCaseMetadata(description="", priority=0)
    def agent_test_suite(self, node: Node, variables: Dict[str, Any], log_path: str, log: Logger) -> None:
        """
        Executes each of the AgentTests included in the "c_test_suites" variable (which is generated by the AgentTestSuitesCombinator).
        """
        self._set_context(node, variables, log_path, log)

        with _set_thread_name(self.context.image_name):  # The thread name is added to self._log
            self._log.info(
                "Test suite parameters:  [test_suites: %s] [skip_setup: %s] [collect_logs: %s]",
                [t.name for t in self.context.test_suites], self.context.skip_setup, self.context.collect_logs)

            test_suite_success = True

            try:
                if not self.context.skip_setup:
                    self._setup()

                try:
                    if not self.context.skip_setup:
                        self._setup_node()

                    # pylint seems to think self.context.test_suites is not iterable. Suppressing warning, since its type is List[AgentTestSuite]
                    #  E1133: Non-iterable value self.context.test_suites is used in an iterating context (not-an-iterable)
                    for suite in self.context.test_suites:  # pylint: disable=E1133
                        test_suite_success = self._execute_test_suite(suite) and test_suite_success

                finally:
                    collect = self.context.collect_logs
                    if collect == CollectLogs.Always or collect == CollectLogs.Failed and not test_suite_success:
                        self._collect_node_logs()

            except:   # pylint: disable=bare-except
                # Report the error and raise and exception to let LISA know that the test errored out.
                self._log.exception("TEST FAILURE DUE TO AN UNEXPECTED ERROR")
                raise Exception("Stopping test execution due to an unexpected error in the test suite")

            finally:
                self._clean_up()

    def _execute_test_suite(self, suite: TestSuiteInfo) -> bool:
        """
        Executes the given test suite and returns True if all the tests in the suite succeeded.
        """
        suite_name = suite.name
        suite_full_name = f"{suite_name}-{self.context.image_name}"
        suite_start_time: datetime.datetime = datetime.datetime.now()

        success: bool = True  # True if all the tests succeed

        with _set_thread_name(suite_full_name):  # The thread name is added to self._log
            with set_current_thread_log(self.context.log_path/f"{suite_full_name}.log"):
                try:
                    agent_test_logger.info("")
                    agent_test_logger.info("**************************************** %s ****************************************", suite_name)
                    agent_test_logger.info("")

                    summary: List[str] = []

                    for test in suite.tests:
                        test_name = test.__name__
                        test_full_name = f"{suite_name}-{test_name}"
                        test_start_time: datetime.datetime = datetime.datetime.now()

                        agent_test_logger.info("******** Executing %s", test_name)
                        self._log.info("******** Executing %s", test_full_name)

                        try:

                            test(self.context).run()

                            summary.append(f"[Passed] {test_name}")
                            agent_test_logger.info("******** [Passed] %s", test_name)
                            self._log.info("******** [Passed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test_name,
                                TestStatus.PASSED,
                                test_start_time)
                        except AssertionError as e:
                            success = False
                            summary.append(f"[Failed] {test_name}")
                            agent_test_logger.error("******** [Failed] %s: %s", test_name, e)
                            self._log.error("******** [Failed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test_name,
                                TestStatus.FAILED,
                                test_start_time,
                                message=str(e))
                        except:  # pylint: disable=bare-except
                            success = False
                            summary.append(f"[Error] {test_name}")
                            agent_test_logger.exception("UNHANDLED EXCEPTION IN %s", test_name)
                            self._log.exception("UNHANDLED EXCEPTION IN %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test_name,
                                TestStatus.FAILED,
                                test_start_time,
                                message="Unhandled exception.",
                                add_exception_stack_trace=True)

                        agent_test_logger.info("")

                    agent_test_logger.info("********* [Test Results]")
                    agent_test_logger.info("")
                    for r in summary:
                        agent_test_logger.info("\t%s", r)
                    agent_test_logger.info("")

                except:  # pylint: disable=bare-except
                    success = False
                    self._report_test_result(
                        suite_full_name,
                        suite_name,
                        TestStatus.FAILED,
                        suite_start_time,
                        message=f"Unhandled exception while executing test suite {suite_name}.",
                        add_exception_stack_trace=True)

        return success

    @staticmethod
    def _report_test_result(
            suite_name: str,
            test_name: str,
            status: TestStatus,
            start_time: datetime.datetime,
            message: str = "",
            add_exception_stack_trace: bool = False
    ) -> None:
        """
        Reports a test result to the junit notifier
        """
        # The junit notifier requires an initial RUNNING message in order to register the test in its internal cache.
        msg: TestResultMessage = TestResultMessage()
        msg.type = "AgentTestResultMessage"
        msg.id_ = str(uuid.uuid4())
        msg.status = TestStatus.RUNNING
        msg.suite_full_name = suite_name
        msg.suite_name = msg.suite_full_name
        msg.full_name = test_name
        msg.name = msg.full_name
        msg.elapsed = 0

        notifier.notify(msg)

        # Now send the actual result. The notifier pipeline makes a deep copy of the message so it is OK to re-use the
        # same object and just update a few fields. If using a different object, be sure that the "id_" is the same.
        msg.status = status
        msg.message = message
        if add_exception_stack_trace:
            msg.stacktrace = traceback.format_exc()
        msg.elapsed = (datetime.datetime.now() - start_time).total_seconds()

        notifier.notify(msg)


