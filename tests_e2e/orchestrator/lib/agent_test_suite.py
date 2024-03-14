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
import datetime
import json
import logging
import time
import traceback
import uuid

from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Tuple

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import (  # pylint: disable=E0401
    Environment,
    Logger,
    notifier,
    simple_requirement,
    TestCaseMetadata,
    TestSuite as LisaTestSuite,
    TestSuiteMetadata,
)
from lisa.environment import EnvironmentStatus  # pylint: disable=E0401
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401
from lisa.node import LocalNode  # pylint: disable=E0401
from lisa.util.constants import RUN_ID  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.common import get_node_context  # pylint: disable=E0401
from lisa.sut_orchestrator.azure.platform_ import AzurePlatform  # pylint: disable=E0401

import makepkg
from azurelinuxagent.common.version import AGENT_VERSION

from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VirtualMachineScaleSetClient

import tests_e2e
from tests_e2e.orchestrator.lib.agent_test_loader import TestSuiteInfo
from tests_e2e.tests.lib.agent_log import AgentLog, AgentLogRecord
from tests_e2e.tests.lib.agent_test import TestSkipped, RemoteTestError
from tests_e2e.tests.lib.agent_test_context import AgentTestContext, AgentVmTestContext, AgentVmssTestContext
from tests_e2e.tests.lib.logging import log, set_thread_name, set_current_thread_log
from tests_e2e.tests.lib.network_security_rule import NetworkSecurityRule
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient
from tests_e2e.tests.lib.shell import run_command, CommandError
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
# Possible values for the collect_logs parameter
#
class CollectLogs(object):
    Always = 'always'   # Always collect logs
    Failed = 'failed'   # Collect logs only on test failures
    No = 'no'           # Never collect logs


#
# Possible values for the keep_environment parameter
#
class KeepEnvironment(object):
    Always = 'always'   # Do not delete resources created by the test suite
    Failed = 'failed'   # Skip delete only on test failures
    No = 'no'           # Always delete resources created by the test suite


class TestFailedException(Exception):
    def __init__(self, env_name: str, test_cases: List[str]):
        msg = "Test suite {0} failed.".format(env_name)
        if test_cases:
            msg += " Failed tests: " + ','.join(test_cases)
        super().__init__(msg)


class _TestNode(object):
    """
    Name and IP address of a test VM
    """
    def __init__(self, name: str, ip_address: str):
        self.name = name
        self.ip_address = ip_address

    def __str__(self):
        return f"{self.name}:{self.ip_address}"


@TestSuiteMetadata(area="waagent", category="", description="")
class AgentTestSuite(LisaTestSuite):
    """
    Manages the setup of test VMs and execution of Agent test suites. This class acts as the interface with the LISA framework, which
    will invoke the execute() method when a runbook is executed.
    """
    def __init__(self, metadata: TestSuiteMetadata) -> None:
        super().__init__(metadata)
        self._working_directory: Path  # Root directory for temporary files
        self._log_path: Path  # Root directory for log files
        self._pypy_x64_path: Path  # Path to the Pypy x64 download
        self._pypy_arm64_path: Path  # Path to the Pypy ARM64 download
        self._test_agent_package_path: Path  # Path to the package for the test Agent
        self._test_source_directory: Path  # Root directory of the source code for the end-to-end tests
        self._test_tools_tarball_path: Path  # Path to the tarball with the tools needed on the test node

        self._runbook_name: str  # name of the runbook execution, used as prefix on ARM resources created by the AgentTestSuite

        self._lisa_log: Logger  # Main log for the LISA run

        self._lisa_environment_name: str  # Name assigned by LISA to the test environment, useful for correlation with LISA logs
        self._environment_name: str  # Name assigned by the AgentTestSuiteCombinator to the test environment

        self._test_suites: List[AgentTestSuite]  # Test suites to execute in the environment

        self._test_args: str  # Additional arguments pass to the test suite

        self._cloud: str  # Azure cloud where test VMs are located
        self._subscription_id: str  # Azure subscription where test VMs are located
        self._location: str  # Azure location (region) where test VMs are located
        self._image: str   # Image used to create the test VMs; it can be empty if LISA chose the size, or when using an existing VM

        self._is_vhd: bool  # True when the test VMs were created by LISA from a VHD; this is usually used to validate a new VHD and the test Agent is not installed

        # username and public SSH key for the admin account used to connect to the test VMs
        self._user: str
        self._identity_file: str

        # If not empty, adds a Network Security Rule allowing SSH access from the specified IP address to any test VMs created by the test suite.
        self._allow_ssh: str

        self._skip_setup: bool  # If True, skip the setup of the test VMs
        self._collect_logs: str  # Whether to collect logs from the test VMs (one of 'always', 'failed', or 'no')
        self._keep_environment: str  # Whether to skip deletion of the resources created by the test suite (one of 'always', 'failed', or 'no')

        # Resource group and VM/VMSS for the test machines. self._vm_name and self._vmss_name are mutually exclusive, only one of them will be set.
        self._resource_group_name: str
        self._vm_name: str
        self._vm_ip_address: str
        self._vmss_name: str

        self._test_nodes: List[_TestNode]  # VMs or scale set instances the tests will run on

        # Whether to create and delete a scale set.
        self._create_scale_set: bool
        self._delete_scale_set: bool

    #
    # Test suites within the same runbook may be executed concurrently, and we need to keep track of how many resource
    # groups are being created. We use this lock and counter to allow only 1 thread to increment the resource group
    # count.
    #
    _rg_count_lock = RLock()
    _rg_count = 0

    def _initialize(self, environment: Environment, variables: Dict[str, Any], lisa_working_path: str, lisa_log_path: str, lisa_log: Logger):
        """
        Initializes the AgentTestSuite from the data passed as arguments by LISA.

        NOTE: All the interface with LISA should be confined to this method. The rest of the test code should not have any dependencies on LISA.
        """
        self._working_directory = self._get_working_directory(lisa_working_path)
        self._log_path = self._get_log_path(variables, lisa_log_path)
        self._test_agent_package_path = self._working_directory/"eggs"/f"WALinuxAgent-{AGENT_VERSION}.zip"
        self._test_source_directory = Path(tests_e2e.__path__[0])
        self._test_tools_tarball_path = self._working_directory/"waagent-tools.tar"
        self._pypy_x64_path = Path("/tmp/pypy3.7-x64.tar.bz2")
        self._pypy_arm64_path = Path("/tmp/pypy3.7-arm64.tar.bz2")

        self._runbook_name = variables["name"]

        self._lisa_log = lisa_log

        self._lisa_environment_name = environment.name
        self._environment_name = variables["c_env_name"]

        self._test_suites = variables["c_test_suites"]
        self._test_args = variables["test_args"]

        self._cloud = variables["cloud"]
        self._subscription_id = variables["subscription_id"]
        self._location = variables["c_location"]
        self._image = variables["c_image"]

        self._is_vhd = variables["c_is_vhd"]

        self._user = variables["user"]
        self._identity_file = variables["identity_file"]

        self._allow_ssh = variables["allow_ssh"]

        self._skip_setup = variables["skip_setup"]
        self._keep_environment = variables["keep_environment"]
        self._collect_logs = variables["collect_logs"]

        # The AgentTestSuiteCombinator can create 4 kinds of platform/environment combinations:
        #
        #    * New VM
        #      The VM is created by LISA. The platform will be 'azure' and the environment will contain a single 'remote' node.
        #
        #    * Existing VM
        #      The VM was passed as argument to the runbook. The platform will be 'ready' and the environment will contain a single 'remote' node.
        #
        #    * New VMSS
        #      The AgentTestSuite will create the scale set before executing the tests. The platform will be 'ready' and the environment will a single 'local' node.
        #
        #    * Existing VMSS
        #      The VMSS was passed as argument to the runbook. The platform will be 'ready' and the environment will contain a list of 'remote' nodes,
        #      one for each instance of the scale set.
        #

        # Note that _vm_name and _vmss_name are mutually exclusive, only one of them will be set.
        self._vm_name = None
        self._vm_ip_address = None
        self._vmss_name = None
        self._create_scale_set = False
        self._delete_scale_set = False

        if isinstance(environment.nodes[0], LocalNode):
            # We need to create a new VMSS.
            # Use the same naming convention as LISA for the scale set name: lisa-<runbook name>-<run id>-<rg_name>-n0,
            # except that, for the "rg_name", LISA uses "e" as prefix (e.g. "e0", "e1", etc.), while we use "w" (for
            # WALinuxAgent, e.g. "w0", "w1", etc.) to avoid name collisions. Also, note that we hardcode the scale set name
            # to "n0" since we are creating a single scale set. Lastly, the resource group name cannot have any uppercase
            # characters, because the publicIP cannot have uppercase characters in its domain name label.
            AgentTestSuite._rg_count_lock.acquire()
            try:
                self._resource_group_name = f"lisa-{self._runbook_name.lower()}-{RUN_ID}-w{AgentTestSuite._rg_count}"
                AgentTestSuite._rg_count += 1
            finally:
                AgentTestSuite._rg_count_lock.release()
            self._vmss_name = f"{self._resource_group_name}-n0"
            self._test_nodes = []  # we'll fill this up when the scale set is created
            self._create_scale_set = True
            self._delete_scale_set = False  # we set it to True once we create the scale set
        else:
            # Else we are using a VM that was created by LISA, or an existing VM/VMSS
            node_context = get_node_context(environment.nodes[0])

            if isinstance(environment.nodes[0].features._platform, AzurePlatform):  # The test VM was created by LISA
                self._resource_group_name = node_context.resource_group_name
                self._vm_name = node_context.vm_name
                self._vm_ip_address = environment.nodes[0].connection_info['address']
                self._test_nodes = [_TestNode(self._vm_name, self._vm_ip_address)]
            else:  # An existing VM/VMSS was passed as argument to the runbook
                self._resource_group_name = variables["resource_group_name"]
                if variables["vm_name"] != "":
                    self._vm_name = variables["vm_name"]
                    self._vm_ip_address = environment.nodes[0].connection_info['address']
                    self._test_nodes = [_TestNode(self._vm_name, self._vm_ip_address)]
                else:
                    self._vmss_name = variables["vmss_name"]
                    self._test_nodes = [_TestNode(node.name, node.connection_info['address']) for node in environment.nodes.list()]

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
        # where "<--working_path>" is the value given to the --working_path command line argument. Create the working directory for
        # the AgentTestSuite as
        #     "<--working_path>/20230322/20230322-194430-287/waagent
        # This directory will be unique for each execution of the runbook ("20230322-194430" is the timestamp and "287" is a
        # unique ID per execution)
        return Path(lisa_working_path).parent.parent/"waagent"

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
            if not self._working_directory.exists():
                log.info("Creating working directory: %s", self._working_directory)
                self._working_directory.mkdir(parents=True)
        finally:
            self._working_directory_lock.release()

    def _setup_test_run(self) -> None:
        """
        Prepares the test suite for execution (currently, it just builds the agent package)

        Returns the path to the agent package.
        """
        self._setup_lock.acquire()

        try:
            completed: Path = self._working_directory / "completed"

            if completed.exists():
                log.info("Found %s. Build has already been done, skipping.", completed)
                return

            log.info("")
            log.info("********************************** [Preparing Test Run] **********************************")
            log.info("")

            self._lisa_log.info("Building agent package to %s", self._test_agent_package_path)
            log.info("Building agent package to %s", self._test_agent_package_path)
            makepkg.run(agent_family="Test", output_directory=str(self._working_directory), log=log)
            if not self._test_agent_package_path.exists():  # the target path is created by makepkg, ensure we are using the correct value
                raise Exception(f"The test Agent package was not created at the expected path {self._test_agent_package_path}")

            #
            # Ensure that Pypy (both x64 and ARM) has been downloaded to the local machine; it is pre-downloaded to /tmp on
            # the container image used for Azure Pipelines runs, but for developer runs it may need to be downloaded.
            #
            for pypy in [self._pypy_x64_path, self._pypy_arm64_path]:
                if pypy.exists():
                    log.info("Found Pypy at %s", pypy)
                else:
                    pypy_download = f"https://dcrdata.blob.core.windows.net/python/{pypy.name}"
                    self._lisa_log.info("Downloading %s to %s", pypy_download, pypy)
                    log.info("Downloading %s to %s", pypy_download, pypy)
                    run_command(["wget", pypy_download, "-O",  pypy])

            #
            # Create a tarball with the tools we need to copy to the test node. The tarball includes two directories:
            #
            #     * bin - Executables file (Bash and Python scripts)
            #     * lib - Library files (Python modules)
            #
            self._lisa_log.info("Creating %s with the tools needed on the test node", self._test_tools_tarball_path)
            log.info("Creating %s with the tools needed on the test node", self._test_tools_tarball_path)
            log.info("Adding orchestrator/scripts")
            command = "cd {0} ; tar cf {1} --transform='s,^,bin/,' *".format(self._test_source_directory/"orchestrator"/"scripts", self._test_tools_tarball_path)
            log.info("%s", command)
            run_command(command, shell=True)
            log.info("Adding tests/scripts")
            command = "cd {0} ; tar rf {1} --transform='s,^,bin/,' *".format(self._test_source_directory/"tests"/"scripts", self._test_tools_tarball_path)
            log.info("%s", command)
            run_command(command, shell=True)
            log.info("Adding tests/lib")
            command = "cd {0} ; tar rf {1} --transform='s,^,lib/,' --exclude=__pycache__ tests_e2e/tests/lib".format(self._test_source_directory.parent, self._test_tools_tarball_path)
            log.info("%s", command)
            run_command(command, shell=True)
            log.info("Contents of %s:\n%s", self._test_tools_tarball_path, run_command(['tar', 'tvf', str(self._test_tools_tarball_path)]))

            log.info("Completed setup, creating %s", completed)
            completed.touch()

        finally:
            self._setup_lock.release()

    def _clean_up(self, success: bool) -> None:
        """
        Cleans up any items created by the test suite run.
        """
        if self._delete_scale_set:
            if self._keep_environment == KeepEnvironment.Always:
                log.info("Won't delete the scale set %s, per the test suite configuration.", self._vmss_name)
            elif self._keep_environment == KeepEnvironment.No or self._keep_environment == KeepEnvironment.Failed and success:
                try:
                    self._lisa_log.info("Deleting resource group containing the test VMSS: %s", self._resource_group_name)
                    resource_group = ResourceGroupClient(cloud=self._cloud, location=self._location, subscription=self._subscription_id, name=self._resource_group_name)
                    resource_group.delete()
                except Exception as error:  # pylint: disable=broad-except
                    log.warning("Error deleting resource group %s: %s", self._resource_group_name, error)

    def _setup_test_nodes(self) -> None:
        """
        Prepares the test nodes for execution of the test suite (installs tools and the test agent, etc)
        """
        install_test_agent = self._test_suites[0].install_test_agent  # All suites in the environment have the same value for install_test_agent

        log.info("")
        log.info("************************************ [Test Nodes Setup] ************************************")
        log.info("")
        for node in self._test_nodes:
            self._lisa_log.info(f"Setting up test node {node}")
            log.info("Test Node: %s", node.name)
            log.info("IP Address: %s", node.ip_address)
            log.info("")

            ssh_client = SshClient(ip_address=node.ip_address, username=self._user, identity_file=Path(self._identity_file))

            self._check_ssh_connectivity(ssh_client)

            #
            # Cleanup the test node (useful for developer runs)
            #
            log.info('Preparing the test node for setup')
            # Note that removing lib requires sudo, since a Python cache may have been created by tests using sudo
            ssh_client.run_command("rm -rvf ~/{bin,lib,tmp}", use_sudo=True)

            #
            # Copy Pypy, the test Agent, and the test tools to the test node
            #
            ssh_client = SshClient(ip_address=node.ip_address, username=self._user, identity_file=Path(self._identity_file))
            if ssh_client.get_architecture() == "aarch64":
                pypy_path = self._pypy_arm64_path
            else:
                pypy_path = self._pypy_x64_path
            target_path = Path("~")/"tmp"
            ssh_client.run_command(f"mkdir {target_path}")
            log.info("Copying %s to %s:%s", pypy_path, node.name, target_path)
            ssh_client.copy_to_node(pypy_path, target_path)
            log.info("Copying %s to %s:%s", self._test_agent_package_path, node.name, target_path)
            ssh_client.copy_to_node(self._test_agent_package_path, target_path)
            log.info("Copying %s to %s:%s", self._test_tools_tarball_path, node.name, target_path)
            ssh_client.copy_to_node(self._test_tools_tarball_path, target_path)

            #
            # Extract the tarball with the test tools. The tarball includes two directories:
            #
            #     * bin - Executables file (Bash and Python scripts)
            #     * lib - Library files (Python modules)
            #
            # After extracting the tarball on the test node, 'bin' will be added to PATH and PYTHONPATH will be set to 'lib'.
            #
            # Note that executables are placed directly under 'bin', while the path for Python modules is preserved under 'lib.
            #
            log.info('Installing tools on the test node')
            command = f"tar xvf {target_path/self._test_tools_tarball_path.name} && ~/bin/install-tools"
            log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command))

            if self._is_vhd:
                log.info("Using a VHD; will not install the Test Agent.")
            elif not install_test_agent:
                log.info("Will not install the Test Agent per the test suite configuration.")
            else:
                log.info("Installing the Test Agent on the test node")
                command = f"install-agent --package ~/tmp/{self._test_agent_package_path.name} --version {AGENT_VERSION}"
                log.info("%s\n%s", command, ssh_client.run_command(command, use_sudo=True))

            log.info("Completed test node setup")

    @staticmethod
    def _check_ssh_connectivity(ssh_client: SshClient) -> None:
        # We may be trying to connect to the test node while it is still booting. Execute a simple command to check that SSH is ready,
        # and raise an exception if it is not after a few attempts.
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                log.info("Checking SSH connectivity to the test node...")
                ssh_client.run_command("echo 'SSH connectivity check'")
                log.info("SSH is ready.")
                break
            except CommandError as error:
                # Check for "System is booting up. Unprivileged users are not permitted to log in yet. Please come back later. For technical details, see pam_nologin(8)."
                if not any(m in error.stderr for m in ["Unprivileged users are not permitted to log in yet", "Permission denied", "Connection reset by peer"]):
                    raise
                if attempt >= max_attempts - 1:
                    raise Exception(f"SSH connectivity check failed after {max_attempts} attempts, giving up [{error}]")
                log.info("SSH is not ready [%s], will retry after a short delay.", error)
                time.sleep(15)

    def _collect_logs_from_test_nodes(self) -> None:
        """
        Collects the test logs from the test nodes and copies them to the local machine
        """
        for node in self._test_nodes:
            node_name = node.name
            ssh_client = SshClient(ip_address=node.ip_address, username=self._user, identity_file=Path(self._identity_file))
            try:
                # Collect the logs on the test machine into a compressed tarball
                self._lisa_log.info("Collecting logs on test node %s", node_name)
                log.info("Collecting logs on test node %s", node_name)
                stdout = ssh_client.run_command("collect-logs", use_sudo=True)
                log.info(stdout)

                # Copy the tarball to the local logs directory
                tgz_name = self._environment_name
                if len(self._test_nodes) > 1:
                    # Append instance of scale set to the end of tarball name
                    tgz_name += '_' + node_name.split('_')[-1]
                remote_path = "/tmp/waagent-logs.tgz"
                local_path = self._log_path / '{0}.tgz'.format(tgz_name)
                log.info("Copying %s:%s to %s", node_name, remote_path, local_path)
                ssh_client.copy_from_node(remote_path, local_path)

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
    def main(self, environment: Environment, variables: Dict[str, Any], working_path: str, log_path: str, log: Logger):  # pylint: disable=redefined-outer-name
        """
        Entry point from LISA
        """
        self._initialize(environment, variables, working_path, log_path, log)
        self._execute()

    def _execute(self) -> None:
        unexpected_error = False
        test_suite_success = True

        # Set the thread name to the name of the environment. The thread name is added to each item in LISA's log.
        with set_thread_name(self._environment_name):
            log_path: Path = self._log_path / f"env-{self._environment_name}.log"
            with set_current_thread_log(log_path):
                start_time: datetime.datetime = datetime.datetime.now()
                failed_cases = []

                try:
                    # Log the environment's name and the variables received from the runbook (note that we need to expand the names of the test suites)
                    log.info("LISA Environment (for correlation with the LISA log): %s", self._lisa_environment_name)
                    log.info("Test suites: %s", [t.name for t in self._test_suites])

                    self._create_working_directory()

                    if not self._skip_setup:
                        self._setup_test_run()

                    try:
                        test_context = self._create_test_context()
                        test_args = self._get_test_args()

                        if not self._skip_setup:
                            try:
                                self._setup_test_nodes()
                            except:
                                test_suite_success = False
                                raise

                        check_log_start_time = datetime.datetime.min

                        for suite in self._test_suites:
                            log.info("Executing test suite %s", suite.name)
                            self._lisa_log.info("Executing Test Suite %s", suite.name)
                            case_success, check_log_start_time = self._execute_test_suite(suite, test_context, test_args, check_log_start_time)
                            test_suite_success = case_success and test_suite_success
                            if not case_success:
                                failed_cases.append(suite.name)

                    finally:
                        if self._collect_logs == CollectLogs.Always or self._collect_logs == CollectLogs.Failed and not test_suite_success:
                            self._collect_logs_from_test_nodes()

                except Exception as e:   # pylint: disable=bare-except
                    # Report the error and raise an exception to let LISA know that the test errored out.
                    unexpected_error = True
                    log.exception("UNEXPECTED ERROR.")
                    self._report_test_result(
                        self._environment_name,
                        "Unexpected Error",
                        TestStatus.FAILED,
                        start_time,
                        message="UNEXPECTED ERROR.",
                        add_exception_stack_trace=True)

                    raise Exception(f"[{self._environment_name}] Unexpected error in AgentTestSuite: {e}")

                finally:
                    self._clean_up(test_suite_success and not unexpected_error)
                    if unexpected_error:
                        self._mark_log_as_failed()

                    # Check if any test failures or unexpected errors occurred. If so, raise an Exception here so that
                    # lisa marks the environment as failed. Otherwise, lisa would mark this environment as passed and
                    # clean up regardless of the value of 'keep_environment'. This should be the last thing that
                    # happens during suite execution.
                    if not test_suite_success or unexpected_error:
                        raise TestFailedException(self._environment_name, failed_cases)

    def _execute_test_suite(self, suite: TestSuiteInfo, test_context: AgentTestContext, test_args: Dict[str, str], check_log_start_time: datetime.datetime) -> Tuple[bool, datetime.datetime]:
        """
        Executes the given test suite and returns a tuple of a bool indicating whether all the tests in the suite succeeded, and the timestamp that should be used
        for the next check of the agent log.
        """
        suite_name = suite.name
        suite_full_name = f"{suite_name}-{self._environment_name}"
        suite_start_time: datetime.datetime = datetime.datetime.now()
        check_log_start_time_override = datetime.datetime.max  # tests can override the timestamp for the agent log check with the get_ignore_errors_before_timestamp() method

        with set_thread_name(suite_full_name):  # The thread name is added to the LISA log
            log_path: Path = self._log_path / f"{suite_full_name}.log"
            with set_current_thread_log(log_path):
                suite_success: bool = True

                try:
                    log.info("")
                    log.info("**************************************** %s ****************************************", suite_name)
                    log.info("")

                    summary: List[str] = []
                    ignore_error_rules: List[Dict[str, Any]] = []

                    for test in suite.tests:
                        test_full_name = f"{suite_name}-{test.name}"
                        test_start_time: datetime.datetime = datetime.datetime.now()

                        log.info("******** Executing %s", test.name)
                        self._lisa_log.info("Executing test %s", test_full_name)

                        test_success: bool = True

                        test_instance = test.test_class(test_context, test_args)
                        try:
                            test_instance.run()
                            summary.append(f"[Passed]  {test.name}")
                            log.info("******** [Passed] %s", test.name)
                            self._lisa_log.info("[Passed] %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.PASSED,
                                test_start_time)
                        except TestSkipped as e:
                            summary.append(f"[Skipped] {test.name}")
                            log.info("******** [Skipped] %s: %s", test.name, e)
                            self._lisa_log.info("******** [Skipped] %s", test_full_name)
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
                            self._lisa_log.error("******** [Failed] %s", test_full_name)
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
                            self._lisa_log.error("******** [Failed] %s", test_full_name)
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
                            self._lisa_log.exception("UNEXPECTED ERROR IN %s", test_full_name)
                            self._report_test_result(
                                suite_full_name,
                                test.name,
                                TestStatus.FAILED,
                                test_start_time,
                                message="Unexpected error.",
                                add_exception_stack_trace=True)

                        log.info("")

                        suite_success = suite_success and test_success

                        ignore_error_rules.extend(test_instance.get_ignore_error_rules())

                        # Check if the test is requesting to override the timestamp for the agent log check.
                        # Note that if multiple tests in the suite provide an override, we'll use the earliest timestamp.
                        test_check_log_start_time = test_instance.get_ignore_errors_before_timestamp()
                        if test_check_log_start_time != datetime.datetime.min:
                            check_log_start_time_override = min(check_log_start_time_override, test_check_log_start_time)

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

                next_check_log_start_time = datetime.datetime.utcnow()
                suite_success = suite_success and self._check_agent_log_on_test_nodes(ignore_error_rules, check_log_start_time_override if check_log_start_time_override != datetime.datetime.max else check_log_start_time)

                return suite_success, next_check_log_start_time

    def _check_agent_log_on_test_nodes(self, ignore_error_rules: List[Dict[str, Any]], check_log_start_time: datetime.datetime) -> bool:
        """
        Checks the agent log on the test nodes for errors; returns true on success (no errors in the logs)
        """
        success: bool = True

        for node in self._test_nodes:
            node_name = node.name
            ssh_client = SshClient(ip_address=node.ip_address, username=self._user, identity_file=Path(self._identity_file))

            test_result_name = self._environment_name
            if len(self._test_nodes) > 1:
                # If there are multiple test nodes, as in a scale set, append the name of the node to the name of the result
                test_result_name += '_' + node_name.split('_')[-1]

            start_time: datetime.datetime = datetime.datetime.now()

            try:
                message = f"Checking agent log on test node {node_name}, starting at {check_log_start_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}"
                self._lisa_log.info(message)
                log.info(message)

                output = ssh_client.run_command("check-agent-log.py -j")
                errors = json.loads(output, object_hook=AgentLogRecord.from_dictionary)

                # Filter out errors that occurred before the starting timestamp or that match an ignore rule
                errors = [e for e in errors if e.timestamp >= check_log_start_time and (len(ignore_error_rules) == 0 or not AgentLog.matches_ignore_rule(e, ignore_error_rules))]

                if len(errors) == 0:
                    # If no errors, we are done; don't create a log or test result.
                    log.info("There are no errors in the agent log")
                else:
                    message = f"Detected {len(errors)} error(s) in the agent log on {node_name}"
                    self._lisa_log.error(message)
                    log.error("%s:\n\n%s\n", message, '\n'.join(['\t\t' + e.text.replace('\n', '\n\t\t') for e in errors]))
                    self._mark_log_as_failed()
                    success = False

                    self._report_test_result(
                        test_result_name,
                        "CheckAgentLog",
                        TestStatus.FAILED,
                        start_time,
                        message=message + ' - First few errors:\n' + '\n'.join([e.text for e in errors[0:3]]))
            except:    # pylint: disable=bare-except
                log.exception("Error checking agent log on %s", node_name)
                success = False
                self._report_test_result(
                    test_result_name,
                    "CheckAgentLog",
                    TestStatus.FAILED,
                    start_time,
                    "Error checking agent log",
                    add_exception_stack_trace=True)

        return success

    def _create_test_context(self,) -> AgentTestContext:
        """
        Creates the context for the test run.
        """
        if self._vm_name is not None:
            self._lisa_log.info("Creating test context for virtual machine")
            vm: VirtualMachineClient = VirtualMachineClient(
                cloud=self._cloud,
                location=self._location,
                subscription=self._subscription_id,
                resource_group=self._resource_group_name,
                name=self._vm_name)
            return AgentVmTestContext(
                working_directory=self._working_directory,
                vm=vm,
                ip_address=self._vm_ip_address,
                username=self._user,
                identity_file=self._identity_file)
        else:
            log.info("Creating test context for scale set")
            if self._create_scale_set:
                self._create_test_scale_set()
            else:
                log.info("Using existing scale set %s", self._vmss_name)

            scale_set = VirtualMachineScaleSetClient(
                cloud=self._cloud,
                location=self._location,
                subscription=self._subscription_id,
                resource_group=self._resource_group_name,
                name=self._vmss_name)

            # If we created the scale set, fill up the test nodes
            if self._create_scale_set:
                self._test_nodes = [_TestNode(name=i.instance_name, ip_address=i.ip_address) for i in scale_set.get_instances_ip_address()]

            return AgentVmssTestContext(
                working_directory=self._working_directory,
                vmss=scale_set,
                username=self._user,
                identity_file=self._identity_file)

    def _get_test_args(self) -> Dict[str, str]:
        """
        Returns the arguments to be passed to the test classes
        """
        test_args: Dict[str, str] = {}
        if self._test_args == "":
            return test_args
        for arg in self._test_args.split(','):
            key, value = arg.split('=')
            test_args[key] = value
        return test_args

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

    def _create_test_scale_set(self) -> None:
        """
        Creates a scale set for the test run
        """
        self._lisa_log.info("Creating resource group %s", self._resource_group_name)
        resource_group = ResourceGroupClient(cloud=self._cloud, location=self._location, subscription=self._subscription_id, name=self._resource_group_name)
        resource_group.create()
        self._delete_scale_set = True

        self._lisa_log.info("Creating scale set %s", self._vmss_name)
        log.info("Creating scale set %s", self._vmss_name)
        template, parameters = self._get_scale_set_deployment_template(self._vmss_name)
        resource_group.deploy_template(template, parameters)

    def _get_scale_set_deployment_template(self, scale_set_name: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Returns the deployment template for scale sets and its parameters
        """
        def read_file(path: str) -> str:
            with open(path, "r") as file_:
                return file_.read().strip()

        publisher, offer, sku, version = self._image.replace(":", " ").split(' ')

        template: Dict[str, Any] = json.loads(read_file(str(self._test_source_directory/"orchestrator"/"templates/vmss.json")))

        # Scale sets for some images need to be deployed with 'plan' property
        plan_required_images = ["almalinux", "kinvolk", "erockyenterprisesoftwarefoundationinc1653071250513"]
        if publisher in plan_required_images:
            resources: List[Dict[str, Any]] = template.get('resources')
            for resource in resources:
                if resource.get('type') == "Microsoft.Compute/virtualMachineScaleSets":
                    resource["plan"] = {
                        "name": "[parameters('sku')]",
                        "product": "[parameters('offer')]",
                        "publisher": "[parameters('publisher')]"
                    }

        if self._allow_ssh != '':
            NetworkSecurityRule(template, is_lisa_template=False).add_allow_ssh_rule(self._allow_ssh)

        return template, {
            "username": {"value": self._user},
            "sshPublicKey": {"value": read_file(f"{self._identity_file}.pub")},
            "vmName": {"value": scale_set_name},
            "publisher": {"value": publisher},
            "offer": {"value": offer},
            "sku": {"value": sku},
            "version": {"value": version}
        }



