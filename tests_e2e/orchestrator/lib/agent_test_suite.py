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
    simple_requirement,
    TestCaseMetadata,
    TestSuite as LisaTestSuite,
    TestSuiteMetadata,
)
from lisa.environment import EnvironmentStatus  # pylint: disable=E0401
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION
from tests_e2e.orchestrator.lib.agent_test_loader import TestSuiteInfo
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.agent_test import TestSkipped, RemoteTestError
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log
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
            self.lisa_log: Logger = None
            self.node: Node = None
            self.runbook_name: str = None
            self.environment_name: str = None
            self.is_vhd: bool = None
            self.test_suites: List[AgentTestSuite] = None
            self.collect_logs: str = None
            self.skip_setup: bool = None
            self.ssh_client: SshClient = None

    def __init__(self, metadata: TestSuiteMetadata) -> None:
        super().__init__(metadata)
        # The context is initialized by _set_context() via the call to execute()
        self.__context: AgentTestSuite._Context = None

    def _initialize(self, node: Node, variables: Dict[str, Any], lisa_working_path: str, lisa_log_path: str, lisa_log: Logger):
        connection_info = node.connection_info
        node_context = get_node_context(node)

        self.__context = self._Context(
            vm=VmIdentifier(
                cloud=self._get_required_parameter(variables, "cloud"),
                location=self._get_required_parameter(variables, "c_location"),
                subscription=node.features._platform.subscription_id,
                resource_group=node_context.resource_group_name,
                name=node_context.vm_name),
            paths=AgentTestContext.Paths(
                working_directory=self._get_working_directory(lisa_working_path),
                remote_working_directory=Path('/home')/connection_info['username']),
            connection=AgentTestContext.Connection(
                ip_address=connection_info['address'],
                username=connection_info['username'],
                private_key_file=connection_info['private_key_file'],
                ssh_port=connection_info['port']))

        self.__context.log_path = self._get_log_path(variables, lisa_log_path)
        self.__context.lisa_log = lisa_log
        self.__context.node = node
        self.__context.is_vhd = self._get_optional_parameter(variables, "c_vhd") != ""
        self.__context.environment_name = f"{node.os.name}-vhd" if self.__context.is_vhd else self._get_required_parameter(variables, "c_env_name")
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
    def _get_log_path(variables: Dict[str, Any], lisa_log_path: str) -> Path:
        # NOTE: If "log_path" is not given as argument to the runbook, use a path derived from LISA's log for the test suite.
        # That path is derived from LISA's "--log_path" command line argument and has a value similar to
        # "<--log_path>/20230217/20230217-040022-342/tests/20230217-040119-288-agent_test_suite"; use the directory
        # 2 levels up.
        log_path = variables.get("log_path")
        if log_path is not None and len(log_path) > 0:
            return Path(log_path)
        return Path(lisa_log_path).parent.parent

    @staticmethod
    def _get_working_directory(lisa_working_path: str) -> Path:
        # LISA's "working_path" has a value similar to
        #     "<--working_path>/20230322/20230322-194430-287/tests/20230322-194451-333-agent_test_suite
        # where "<--working_path>" is the value given to the --working_path command line argument. Create the working for
        # the AgentTestSuite as
        #     "<--working_path>/20230322/20230322-194430-287/waagent
        # This directory will be unique for each execution of the runbook ("20230322-194430" is the timestamp and "287" is a
        # unique ID per execution)
        return Path(lisa_working_path).parent.parent / "waagent"

    @property
    def context(self):
        if self.__context is None:
            raise Exception("The context for the AgentTestSuite has not been initialized")
        return self.__context

    #
    # Test suites within the same runbook may be executed concurrently, and setup needs to be done only once.
    # We use these locks to allow only 1 thread to do the setup. Setup completion is marked using the 'completed'
    # file: the thread doing the setup creates the file and threads that find that the file already exists
    # simply skip setup.
    #
    _working_directory_lock = RLock()
    _setup_lock = RLock()

    def _create_working_directory(self) -> None:
        """
        Creates the working directory for the test suite.
        """
        self._working_directory_lock.acquire()

        try:
            if not self.context.working_directory.exists():
                log.info("Creating working directory: %s", self.context.working_directory)
                self.context.working_directory.mkdir(parents=True)
        finally:
            self._working_directory_lock.release()

    def _setup(self) -> None:
        """
        Prepares the test suite for execution (currently, it just builds the agent package)

        Returns the path to the agent package.
        """
        self._setup_lock.acquire()

        try:
            log.info("")
            log.info("**************************************** [Build] ****************************************")
            log.info("")
            completed: Path = self.context.working_directory/"completed"

            if completed.exists():
                log.info("Found %s. Build has already been done, skipping.", completed)
                return

            self.context.lisa_log.info("Building test agent")
            self._build_agent_package()

            log.info("Completed setup, creating %s", completed)
            completed.touch()

        finally:
            self._setup_lock.release()

    def _build_agent_package(self) -> None:
        """
        Builds the agent package and returns the path to the package.
        """
        log.info("Building agent package to %s", self.context.working_directory)

        makepkg.run(agent_family="Test", output_directory=str(self.context.working_directory), log=log)

        package_path: Path = self._get_agent_package_path()
        if not package_path.exists():
            raise Exception(f"Can't find the agent package at {package_path}")

        log.info("Built agent package as %s", package_path)

    def _get_agent_package_path(self) -> Path:
        """
        Returns the path to the agent package.
        """
        return self.context.working_directory/"eggs"/f"WALinuxAgent-{AGENT_VERSION}.zip"

    def _clean_up(self) -> None:
        """
        Cleans up any leftovers from the test suite run. Currently just an empty placeholder for future use.
        """

    def _setup_node(self, install_test_agent: bool) -> None:
        """
        Prepares the remote node for executing the test suite (installs tools and the test agent, etc)
        """
        self.context.lisa_log.info("Setting up test node")
        log.info("")
        log.info("************************************** [Node Setup] **************************************")
        log.info("")
        log.info("Test Node: %s", self.context.vm.name)
        log.info("IP Address: %s", self.context.vm_ip_address)
        log.info("Resource Group: %s", self.context.vm.resource_group)
        log.info("")

        #
        # Ensure that the correct version (x84 vs ARM64) Pypy has been downloaded; it is pre-downloaded to /tmp on the container image
        # used for Azure Pipelines runs, but for developer runs it may need to be downloaded.
        #
        if self.context.ssh_client.get_architecture() == "aarch64":
            pypy_path = Path("/tmp/pypy3.7-arm64.tar.bz2")
            pypy_download = "https://dcrdata.blob.core.windows.net/python/pypy3.7-arm64.tar.bz2"
        else:
            pypy_path = Path("/tmp/pypy3.7-x64.tar.bz2")
            pypy_download = "https://dcrdata.blob.core.windows.net/python/pypy3.7-x64.tar.bz2"
        if pypy_path.exists():
            log.info("Found Pypy at %s", pypy_path)
        else:
            log.info("Downloading %s to %s", pypy_download, pypy_path)
            run_command(["wget", pypy_download, "-O",  pypy_path])

        #
        # Create a tarball with the files we need to copy to the test node. The tarball includes two directories:
        #
        #     * bin - Executables file (Bash and Python scripts)
        #     * lib - Library files (Python modules)
        #
        # After extracting the tarball on the test node, 'bin' will be added to PATH and PYTHONPATH will be set to 'lib'.
        #
        # Note that executables are placed directly under 'bin', while the path for Python modules is preserved under 'lib.
        #
        tarball_path: Path = Path("/tmp/waagent.tar")
        log.info("Creating %s with the files need on the test node", tarball_path)
        log.info("Adding orchestrator/scripts")
        command = "cd {0} ; tar cvf {1} --transform='s,^,bin/,' *".format(self.context.test_source_directory/"orchestrator"/"scripts", str(tarball_path))
        log.info("%s\n%s", command, run_command(command, shell=True))
        log.info("Adding tests/scripts")
        command = "cd {0} ; tar rvf {1} --transform='s,^,bin/,' *".format(self.context.test_source_directory/"tests"/"scripts", str(tarball_path))
        log.info("%s\n%s", command, run_command(command, shell=True))
        log.info("Adding tests/lib")
        command = "cd {0} ; tar rvf {1} --transform='s,^,lib/,' --exclude=__pycache__ tests_e2e/tests/lib".format(self.context.test_source_directory.parent, str(tarball_path))
        log.info("%s\n%s", command, run_command(command, shell=True))
        local_tarball_contents = run_command(['tar', 'tvf', str(tarball_path)])
        log.info("Contents of %s:\n\n%s", tarball_path, local_tarball_contents)

        #
        # Cleanup the test node (useful for developer runs)
        #
        log.info('Preparing the test node for setup')
        # Note that removing lib requires sudo, since a Python cache may have been created by tests using sudo
        self.context.ssh_client.run_command("rm -rvf ~/{bin,lib,tmp}", use_sudo=True)

        #
        # Copy the tarball, Pypy and the test Agent to the test node
        #
        target_path = Path("~")/"tmp"
        self.context.ssh_client.run_command(f"mkdir {target_path}")
        log.info("Copying %s to %s:%s", tarball_path, self.context.node.name, target_path)
        self.context.ssh_client.copy_to_node(tarball_path, target_path)
        log.info("Copying %s to %s:%s", pypy_path, self.context.node.name, target_path)
        self.context.ssh_client.copy_to_node(pypy_path, target_path)
        agent_package_path: Path = self._get_agent_package_path()
        log.info("Copying %s to %s:%s", agent_package_path, self.context.node.name, target_path)
        self.context.ssh_client.copy_to_node(agent_package_path, target_path)

        #
        # List the contents of the copied tarball and compare to the contents of the local tarball. If they do not
        # match, retry the copy command.
        #
        retry_tarball_copy = 3
        contents_match = False
        while retry_tarball_copy > 0 and not contents_match:
            test_node_tarball_contents = self.context.ssh_client.run_command(f"tar tvf {target_path / tarball_path.name}")
            log.info("Contents of %s on the test node:\n\n%s", f"{target_path / tarball_path.name}",
                     test_node_tarball_contents)
            if local_tarball_contents == test_node_tarball_contents:
                contents_match = True
            else:
                log.info("Tarball contents on test node do not match local tarball contents - retrying tarball copy...")
                log.info("Copying %s to %s:%s", tarball_path, self.context.node.name, target_path)
                self.context.ssh_client.copy_to_node(tarball_path, target_path)

        #
        # Extract the tarball and execute the install scripts
        #
        log.info('Installing tools on the test node')
        command = f"tar xvf {target_path/tarball_path.name} && ~/bin/install-tools"
        log.info("Remote command [%s] completed:\n%s", command, self.context.ssh_client.run_command(command))

        if self.context.is_vhd:
            log.info("Using a VHD; will not install the Test Agent.")
        elif not install_test_agent:
            log.info("Will not install the Test Agent per the test suite configuration.")
        else:
            log.info("Installing the Test Agent on the test node")
            command = f"install-agent --package ~/tmp/{agent_package_path.name} --version {AGENT_VERSION}"
            log.info("%s\n%s", command, self.context.ssh_client.run_command(command, use_sudo=True))

        log.info("Completed test node setup")

    def _collect_node_logs(self) -> None:
        """
        Collects the test logs from the remote machine and copies them to the local machine
        """
        try:
            # Collect the logs on the test machine into a compressed tarball
            self.context.lisa_log.info("Collecting logs on test node")
            log.info("Collecting logs on test node")
            stdout = self.context.ssh_client.run_command("collect-logs", use_sudo=True)
            log.info(stdout)

            # Copy the tarball to the local logs directory
            remote_path = "/tmp/waagent-logs.tgz"
            local_path = self.context.log_path/'{0}.tgz'.format(self.context.environment_name)
            log.info("Copying %s:%s to %s", self.context.node.name, remote_path, local_path)
            self.context.ssh_client.copy_from_node(remote_path, local_path)

        except:  # pylint: disable=bare-except
            log.exception("Failed to collect logs from the test machine")

    # NOTES:
    #
    #    * environment_status=EnvironmentStatus.Deployed skips most of LISA's initialization of the test node, which is not needed
    #      for agent tests.
    #
    #    * We need to take the LISA Logger using a parameter named 'log'; this parameter hides tests_e2e.tests.lib.logging.log.
    #      Be aware then, that within this method 'log' refers to the LISA log, and elsewhere it refers to tests_e2e.tests.lib.logging.log.
    #
    # W0621: Redefining name 'log' from outer scope (line 53) (redefined-outer-name)
    @TestCaseMetadata(description="", priority=0, requirement=simple_requirement(environment_status=EnvironmentStatus.Deployed))
    def main(self, node: Node, environment: Environment, variables: Dict[str, Any], working_path: str, log_path: str, log: Logger):  # pylint: disable=redefined-outer-name
        """
        Entry point from LISA
        """
        self._initialize(node, variables, working_path, log_path, log)
        self._execute(environment, variables)

    def _execute(self, environment: Environment, variables: Dict[str, Any]):
        """
        Executes each of the AgentTests included in the "c_test_suites" variable (which is generated by the AgentTestSuitesCombinator).
        """
        # Set the thread name to the name of the environment. The thread name is added to each item in LISA's log.
        with _set_thread_name(self.context.environment_name):
            log_path: Path = self.context.log_path/f"env-{self.context.environment_name}.log"
            with set_current_thread_log(log_path):
                start_time: datetime.datetime = datetime.datetime.now()
                success = True

                try:
                    # Log the environment's name and the variables received from the runbook (note that we need to expand the names of the test suites)
                    log.info("LISA Environment (for correlation with the LISA log): %s", environment.name)
                    log.info("Runbook variables:")
                    for name, value in variables.items():
                        log.info("    %s: %s", name, value if name != 'c_test_suites' else [t.name for t in value])

                    test_suite_success = True

                    try:
                        self._create_working_directory()

                        if not self.context.skip_setup:
                            self._setup()

                        if not self.context.skip_setup:
                            # pylint seems to think self.context.test_suites is not iterable. Suppressing this warning here and a few lines below, since
                            # its type is List[AgentTestSuite].
                            # E1133: Non-iterable value self.context.test_suites is used in an iterating context (not-an-iterable)
                            install_test_agent = all([suite.install_test_agent for suite in self.context.test_suites])   # pylint: disable=E1133
                            try:
                                self._setup_node(install_test_agent)
                            except:
                                test_suite_success = False
                                raise

                        for suite in self.context.test_suites:  # pylint: disable=E1133
                            log.info("Executing test suite %s", suite.name)
                            self.context.lisa_log.info("Executing Test Suite %s", suite.name)
                            test_suite_success = self._execute_test_suite(suite) and test_suite_success

                        test_suite_success = self._check_agent_log() and test_suite_success

                    finally:
                        collect = self.context.collect_logs
                        if collect == CollectLogs.Always or collect == CollectLogs.Failed and not test_suite_success:
                            self._collect_node_logs()

                except Exception as e:   # pylint: disable=bare-except
                    # Report the error and raise an exception to let LISA know that the test errored out.
                    success = False
                    log.exception("UNEXPECTED ERROR.")
                    self._report_test_result(
                        self.context.environment_name,
                        "Unexpected Error",
                        TestStatus.FAILED,
                        start_time,
                        message="UNEXPECTED ERROR.",
                        add_exception_stack_trace=True)

                    raise Exception(f"[{self.context.environment_name}] Unexpected error in AgentTestSuite: {e}")

                finally:
                    self._clean_up()
                    if not success:
                        self._mark_log_as_failed()

    def _execute_test_suite(self, suite: TestSuiteInfo) -> bool:
        """
        Executes the given test suite and returns True if all the tests in the suite succeeded.
        """
        suite_name = suite.name
        suite_full_name = f"{suite_name}-{self.context.environment_name}"
        suite_start_time: datetime.datetime = datetime.datetime.now()

        with _set_thread_name(suite_full_name):  # The thread name is added to the LISA log
            log_path: Path = self.context.log_path/f"{suite_full_name}.log"
            with set_current_thread_log(log_path):
                suite_success: bool = True

                try:
                    log.info("")
                    log.info("**************************************** %s ****************************************", suite_name)
                    log.info("")

                    summary: List[str] = []

                    for test in suite.tests:
                        test_full_name = f"{suite_name}-{test.name}"
                        test_start_time: datetime.datetime = datetime.datetime.now()

                        log.info("******** Executing %s", test.name)
                        self.context.lisa_log.info("Executing test %s", test_full_name)

                        test_success: bool = True

                        try:
                            test.test_class(self.context).run()

                            summary.append(f"[Passed]  {test.name}")
                            log.info("******** [Passed] %s", test.name)
                            self.context.lisa_log.info("[Passed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.PASSED,
                                test_start_time)
                        except TestSkipped as e:
                            summary.append(f"[Skipped] {test.name}")
                            log.info("******** [Skipped] %s: %s", test.name, e)
                            self.context.lisa_log.info("******** [Skipped] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.SKIPPED,
                                test_start_time,
                                message=str(e))
                        except AssertionError as e:
                            test_success = False
                            summary.append(f"[Failed]  {test.name}")
                            log.error("******** [Failed] %s: %s", test.name, e)
                            self.context.lisa_log.error("******** [Failed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.FAILED,
                                test_start_time,
                                message=str(e))
                        except RemoteTestError as e:
                            test_success = False
                            summary.append(f"[Failed]  {test.name}")
                            message = f"UNEXPECTED ERROR IN [{e.command}] {e.stderr}\n{e.stdout}"
                            log.error("******** [Failed] %s: %s", test.name, message)
                            self.context.lisa_log.error("******** [Failed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.FAILED,
                                test_start_time,
                                message=str(message))
                        except:  # pylint: disable=bare-except
                            test_success = False
                            summary.append(f"[Error]   {test.name}")
                            log.exception("UNEXPECTED ERROR IN %s", test.name)
                            self.context.lisa_log.exception("UNEXPECTED ERROR IN %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.FAILED,
                                test_start_time,
                                message="Unexpected error.",
                                add_exception_stack_trace=True)

                        log.info("")

                        suite_success = suite_success and test_success

                        if not test_success and test.blocks_suite:
                            log.warning("%s failed and blocks the suite. Stopping suite execution.", test.name)
                            break

                    log.info("")
                    log.info("******** [Test Results]")
                    log.info("")
                    for r in summary:
                        log.info("\t%s", r)
                    log.info("")

                except:  # pylint: disable=bare-except
                    suite_success = False
                    self._report_test_result(
                        suite_full_name,
                        suite_name,
                        TestStatus.FAILED,
                        suite_start_time,
                        message=f"Unhandled exception while executing test suite {suite_name}.",
                        add_exception_stack_trace=True)
                finally:
                    if not suite_success:
                        self._mark_log_as_failed()

                return suite_success

    def _check_agent_log(self) -> bool:
        """
        Checks the agent log for errors; returns true on success (no errors int the log)
        """
        start_time: datetime.datetime = datetime.datetime.now()

        try:
            self.context.lisa_log.info("Checking agent log on the test node")
            log.info("Checking agent log on the test node")

            output = self.context.ssh_client.run_command("check-agent-log.py -j")
            errors = json.loads(output, object_hook=AgentLogRecord.from_dictionary)

            # Individual tests may have rules to ignore known errors; filter those out
            ignore_error_rules = []
            # pylint seems to think self.context.test_suites is not iterable. Suppressing warning, since its type is List[AgentTestSuite]
            #  E1133: Non-iterable value self.context.test_suites is used in an iterating context (not-an-iterable)
            for suite in self.context.test_suites:  # pylint: disable=E1133
                for test in suite.tests:
                    ignore_error_rules.extend(test.test_class(self.context).get_ignore_error_rules())

            if len(ignore_error_rules) > 0:
                new = []
                for e in errors:
                    if not AgentLog.matches_ignore_rule(e, ignore_error_rules):
                        new.append(e)
                errors = new

            if len(errors) == 0:
                # If no errors, we are done; don't create a log or test result.
                log.info("There are no errors in the agent log")
                return True

            message = f"Detected {len(errors)} error(s) in the agent log"
            self.context.lisa_log.error(message)
            log.error("%s:\n\n%s\n", message, '\n'.join(['\t\t' + e.text.replace('\n', '\n\t\t') for e in errors]))
            self._mark_log_as_failed()

            self._report_test_result(
                self.context.environment_name,
                "CheckAgentLog",
                TestStatus.FAILED,
                start_time,
                message=message + ' - First few errors:\n' + '\n'.join([e.text for e in errors[0:3]]))
        except:    # pylint: disable=bare-except
            log.exception("Error checking agent log")
            self._report_test_result(
                self.context.environment_name,
                "CheckAgentLog",
                TestStatus.FAILED,
                start_time,
                "Error checking agent log",
                add_exception_stack_trace=True)

        return False

    @staticmethod
    def _mark_log_as_failed():
        """
        Adds a message to indicate the log contains errors.
        """
        log.info("MARKER-LOG-WITH-ERRORS")

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


