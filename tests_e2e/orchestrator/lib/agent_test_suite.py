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
import json
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
    Environment,
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
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.agent_test import TestSkipped
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log as agent_test_logger  # Logger used by the tests
from tests_e2e.tests.lib.logging import set_current_thread_log
from tests_e2e.tests.lib.agent_log import AgentLogRecord
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
        Prepares the remote node for executing the test suite (installs tools and the test agent, etc)
        """
        self._log.info("")
        self._log.info("************************************** [Node Setup] **************************************")
        self._log.info("")
        self._log.info("Test Node: %s", self.context.vm.name)
        self._log.info("Resource Group: %s", self.context.vm.resource_group)
        self._log.info("")

        self.context.ssh_client.run_command("mkdir -p ~/bin/tests_e2e/tests; touch ~/bin/agent-env")

        # Copy the test tools
        tools_path = self.context.test_source_directory/"orchestrator"/"scripts"
        tools_target_path = Path("~/bin")
        self._log.info("Copying %s to %s:%s", Path("~/bin/pypy3.7.tar.bz2"), self.context.node.name, tools_target_path)
        self.context.ssh_client.copy_to_node(tools_path, tools_target_path, recursive=True)

        # Copy the test libraries
        lib_path = self.context.test_source_directory/"tests"/"lib"
        lib_target_path = Path("~/bin/tests_e2e/tests")
        self._log.info("Copying %s to %s:%s", lib_path, self.context.node.name, lib_target_path)
        self.context.ssh_client.copy_to_node(lib_path, lib_target_path, recursive=True)

        # Copy the test agent
        agent_package_path: Path = self._get_agent_package_path()
        agent_package_target_path = Path("~/bin")/agent_package_path.name
        self._log.info("Copying %s to %s:%s", agent_package_path, self.context.node.name, agent_package_target_path)
        self.context.ssh_client.copy_to_node(agent_package_path, agent_package_target_path)

        # Copy Pypy
        if self.context.ssh_client.get_architecture() == "aarch64":
            pypy_path = Path("/tmp/pypy3.7-arm64.tar.bz2")
            pypy_download = "https://downloads.python.org/pypy/pypy3.7-v7.3.5-aarch64.tar.bz2"
        else:
            pypy_path = Path("/tmp/pypy3.7-x64.tar.bz2")
            pypy_download = "https://downloads.python.org/pypy/pypy3.7-v7.3.5-linux64.tar.bz2"

        if not pypy_path.exists():
            self._log.info(f"Downloading {pypy_download} to {pypy_path}")
            run_command(["wget", pypy_download, "-O",  pypy_path])
        pypy_target_path = Path("~/bin/pypy3.7.tar.bz2")
        self._log.info("Copying %s to %s:%s", pypy_path, self.context.node.name, pypy_target_path)
        self.context.ssh_client.copy_to_node(pypy_path, pypy_target_path)

        # Install the tools and libraries
        install_command = lambda: self.context.ssh_client.run_command(f"~/bin/scripts/install-tools --agent-package {agent_package_target_path}")
        self._log.info('Installing tools on the test node\n%s', install_command())
        self._log.info('Remote commands will use %s', self.context.ssh_client.run_command("which python3"))

        # Install the agent
        if self.context.is_vhd:
            self._log.info("Using a VHD; will not install the Test Agent.")
        else:
            install_command = lambda: self.context.ssh_client.run_command(f"install-agent --package {agent_package_target_path} --version {AGENT_VERSION}", use_sudo=True)
            self._log.info("Installing the Test Agent on %s\n%s", self.context.node.name, install_command())

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
            self.context.ssh_client.copy_from_node(remote_path, local_path)

        except:  # pylint: disable=bare-except
            self._log.exception("Failed to collect logs from the test machine")

    @TestCaseMetadata(description="", priority=0)
    def agent_test_suite(self, node: Node, environment: Environment, variables: Dict[str, Any], log_path: str, log: Logger) -> None:
        """
        Executes each of the AgentTests included in the "c_test_suites" variable (which is generated by the AgentTestSuitesCombinator).
        """
        self._set_context(node, variables, log_path, log)

        # Set the thread name to the image; this name is added to self._log
        with _set_thread_name(self.context.image_name):
            # Log the environment's name and the variables received from the runbook (note that we need to expand the names of the test suites)
            self._log.info("LISA Environment: %s", environment.name)
            self._log.info(
                "Runbook variables:\n%s",
                '\n'.join([f"\t{name}: {value if name != 'c_test_suites' else [t.name for t in value] }" for name, value in variables.items()]))

            start_time: datetime.datetime = datetime.datetime.now()
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

                    test_suite_success = self._check_agent_log() and test_suite_success

                finally:
                    collect = self.context.collect_logs
                    if collect == CollectLogs.Always or collect == CollectLogs.Failed and not test_suite_success:
                        self._collect_node_logs()

            except:   # pylint: disable=bare-except
                # Report the error and raise and exception to let LISA know that the test errored out.
                self._log.exception("TEST FAILURE DUE TO AN UNEXPECTED ERROR.")
                self._report_test_result(
                    self.context.image_name,
                    "Setup",
                    TestStatus.FAILED,
                    start_time,
                    message="TEST FAILURE DUE TO AN UNEXPECTED ERROR.",
                    add_exception_stack_trace=True)

                raise Exception("STOPPING TEST EXECUTION DUE TO AN UNEXPECTED ERROR.")

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

                            summary.append(f"[Passed]  {test_name}")
                            agent_test_logger.info("******** [Passed] %s", test_name)
                            self._log.info("******** [Passed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test_name,
                                TestStatus.PASSED,
                                test_start_time)
                        except TestSkipped as e:
                            summary.append(f"[Skipped] {test_name}")
                            agent_test_logger.info("******** [Skipped] %s: %s", test_name, e)
                            self._log.info("******** [Skipped] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test_name,
                                TestStatus.SKIPPED,
                                test_start_time,
                                message=str(e))
                        except AssertionError as e:
                            success = False
                            summary.append(f"[Failed]  {test_name}")
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
                            summary.append(f"[Error]   {test_name}")
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

    def _check_agent_log(self) -> bool:
        """
        Checks the agent log for errors; returns true on success (no errors int the log)
        """
        start_time: datetime.datetime = datetime.datetime.now()

        self._log.info("Checking agent log on the test node")
        output = self.context.ssh_client.run_command("check-agent-log.py -j")
        errors = json.loads(output, object_hook=AgentLogRecord.from_dictionary)

        # Individual tests may have rules to ignore known errors; filter those out
        ignore_error_rules = []
        # pylint seems to think self.context.test_suites is not iterable. Suppressing warning, since its type is List[AgentTestSuite]
        #  E1133: Non-iterable value self.context.test_suites is used in an iterating context (not-an-iterable)
        for suite in self.context.test_suites:  # pylint: disable=E1133
            for test in suite.tests:
                ignore_error_rules.extend(test(self.context).get_ignore_error_rules())

        if len(ignore_error_rules) > 0:
            new = []
            for e in errors:
                if not AgentLog.matches_ignore_rule(e, ignore_error_rules):
                    new.append(e)
            errors = new

        if len(errors) == 0:
            # If no errors, we are done; don't create a log or test result.
            self._log.info("There are no errors in the agent log")
            return True

        log_path: Path = self.context.log_path/f"CheckAgentLog-{self.context.image_name}.log"
        message = f"Detected {len(errors)} error(s) in the agent log. See {log_path} for a full report."
        self._log.info(message)

        with set_current_thread_log(log_path):
            agent_test_logger.info("Detected %s error(s) in the agent log:\n\n%s", len(errors), '\n'.join(['\t' + e.text for e in errors]))

        self._report_test_result(
            self.context.image_name,
            "CheckAgentLog",
            TestStatus.FAILED,
            start_time,
            message=message + '\n' + '\n'.join([e.text for e in errors[0:3]]),
            add_exception_stack_trace=True)

        return False

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


