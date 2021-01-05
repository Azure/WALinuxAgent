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
# Requires Python 2.4+ and Openssl 1.0+
#

from __future__ import print_function

import os
import random
import re
import subprocess
import tempfile
import time
import threading

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator, UnexpectedProcessesInCGroupException
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.utils import shellutil
from tests.common.mock_cgroup_commands import mock_cgroup_commands
from tests.tools import AgentTestCase, patch, mock_sleep
from tests.utils.miscellaneous_tools import format_processes, wait_for

class CGroupConfiguratorSystemdTestCase(AgentTestCase):
    @classmethod
    def tearDownClass(cls):
        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._instance from unit test for CGroupConfigurator
        CGroupConfigurator._instance = None  # pylint: disable=protected-access
        AgentTestCase.tearDownClass()

    @staticmethod
    def _get_new_cgroup_configurator_instance(initialize=True, mock_commands=None, mock_files=None):
        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._instance from unit test for CGroupConfigurator
        CGroupConfigurator._instance = None  # pylint: disable=protected-access
        configurator = CGroupConfigurator.get_instance()
        CGroupsTelemetry.reset()
        if initialize:
            with mock_cgroup_commands() as mocks:
                if mock_files is not None:
                    for item in mock_files:
                        mocks.add_file(item[0], item[1])
                if mock_commands is not None:
                    for command in mock_commands:
                        mocks.add_command(command[0], command[1])
                configurator.initialize()
        return configurator

    def test_initialize_should_start_tracking_the_agent_cgroups(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

        self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
        self.assertTrue(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'cpu' in cg.path),
            "The Agent's CPU is not being tracked. Tracked: {0}".format(tracked))
        self.assertTrue(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'memory' in cg.path),
            "The Agent's memory is not being tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_start_tracking_other_controllers_when_one_is_not_present(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance(
            mock_commands=[(r"^mount -t cgroup$",
 '''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
 cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
 cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
 cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
 cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
 cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
 cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
 cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
 cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
 cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
 cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
 ''')])

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

        self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
        self.assertFalse(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'cpu' in cg.path),
            "The Agent's CPU should not be tracked. Tracked: {0}".format(tracked))
        self.assertTrue(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'memory' in cg.path),
            "The Agent's memory is not being tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_is_the_cpu_and_memory_controllers_are_not_present(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance(
            mock_commands=[(r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
                            ''')])

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

        self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
        self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_when_the_agent_is_not_in_the_system_slice(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance(
            mock_commands=[(r"^mount -t cgroup$",
                            '''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
                            cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
                            cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
                            cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
                            cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
                            cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
                            cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
                            cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
                            cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
                            cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
                                                        ''')])

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

        self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
        self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))

    def test_enable_and_disable_should_change_the_enabled_state_of_cgroups(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        self.assertTrue(configurator.enabled(), "CGroupConfigurator should be enabled by default")

        configurator.disable()
        self.assertFalse(configurator.enabled(), "disable() should disable the CGroupConfigurator")

        configurator.enable()
        self.assertTrue(configurator.enabled(), "enable() should enable the CGroupConfigurator")

    def test_enable_should_raise_cgroups_exception_when_cgroups_are_not_supported(self):
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported", return_value=False):
            configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance(initialize=False)
            configurator.initialize()

            with self.assertRaises(CGroupsException) as context_manager:
                configurator.enable()
            self.assertIn("Attempted to enable cgroups, but they are not supported on the current platform", str(context_manager.exception))

    def test_disable_should_reset_tracked_cgroups(self):
        # Start tracking a couple of dummy cgroups
        CGroupsTelemetry.track_cgroup(CGroup("dummy", "/sys/fs/cgroup/memory/system.slice/dummy.service", "cpu"))
        CGroupsTelemetry.track_cgroup(CGroup("dummy", "/sys/fs/cgroup/memory/system.slice/dummy.service", "memory"))

        CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance().disable()

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        self.assertEqual(len(CGroupsTelemetry._tracked), 0)  # pylint: disable=protected-access

    def test_cgroup_operations_should_not_invoke_the_cgroup_api_when_cgroups_are_not_enabled(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()
        configurator.disable()

        # List of operations to test, and the functions to mock used in order to do verifications
        operations = [
            [configurator.create_extensions_slice, "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extensions_slice"],
        ]

        for operation in operations:
            with patch(operation[1]) as mock_cgroup_api_operation:
                operation[0]()

            self.assertEqual(mock_cgroup_api_operation.call_count, 0)

    def test_cgroup_operations_should_log_a_warning_when_the_cgroup_api_raises_an_exception(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        # cleanup_legacy_cgroups disables cgroups on error, so make disable() a no-op
        with patch.object(configurator, "disable"):
            # List of operations to test, and the functions to mock in order to raise exceptions
            operations = [
                [configurator.create_extensions_slice, "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extensions_slice"],
            ]

            def raise_exception(*_):
                raise Exception("A TEST EXCEPTION")

            for operation in operations:
                with patch("azurelinuxagent.common.cgroupconfigurator.logger.warn") as mock_logger_warn:
                    with patch(operation[1], raise_exception):
                        operation[0]()

                    self.assertEqual(mock_logger_warn.call_count, 1)

                    args, _ = mock_logger_warn.call_args
                    message = args[0]
                    self.assertIn("A TEST EXCEPTION", message)

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_systemd_when_cgroups_are_not_enabled(self, _):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()
        configurator.disable()

        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as patcher:
            configurator.start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="date",
                timeout=300,
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            command_calls = [args[0] for args, _ in patcher.call_args_list if len(args) > 0 and "date" in args[0]]
            self.assertEqual(len(command_calls), 1, "The test command should have been called exactly once [{0}]".format(command_calls))
            self.assertNotIn("systemd-run", command_calls[0], "The command should not have been invoked using systemd")
            self.assertEqual(command_calls[0], "date", "The command line should not have been modified")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_use_systemd_run_when_cgroups_are_enabled(self, _):
        with mock_cgroup_commands():
            with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance().start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    timeout=300,
                    shell=False,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                command_calls = [args[0] for (args, _) in popen_patch.call_args_list if "the-test-extension-command" in args[0]]

                self.assertEqual(len(command_calls), 1, "The test command should have been called exactly once [{0}]".format(command_calls))
                self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", command_calls[0], "The extension should have been invoked using systemd")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_start_tracking_the_extension_cgroups(self, _):
        # CPU usage is initialized when we begin tracking a CPU cgroup; since this test does not retrieve the
        # CPU usage, there is no need for initialization
        with mock_cgroup_commands():
            CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                timeout=300,
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        # protected-access<W0212> Disabled: OK to access CGroupConfigurator._tracked from unit test for CGroupConfigurator
        tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

        self.assertTrue(
            any(cg for cg in tracked if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
            "The extension's CPU is not being tracked")
        self.assertTrue(
            any(cg for cg in tracked if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'memory' in cg.path),
            "The extension's memory is not being tracked")

    def test_start_extension_command_should_raise_an_exception_when_the_command_cannot_be_started(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        original_popen = subprocess.Popen

        def mock_popen(command_arg, *args, **kwargs):
            if "test command" in command_arg:
                raise Exception("A TEST EXCEPTION")
            return original_popen(command_arg, *args, **kwargs)

        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen):
            with self.assertRaises(Exception) as context_manager:
                configurator.start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="test command",
                    timeout=300,
                    shell=False,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                self.assertIn("A TEST EXCEPTION", str(context_manager.exception))

    def test_check_processes_in_agent_cgroup_should_raise_when_there_are_unexpected_processes_in_the_agent_cgroup(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        # The test script recursively creates a given number of descendant processes, then it blocks until the
        # 'stop_file' exists. It produces an output file containing the PID of each descendant process.
        test_script = os.path.join(self.tmp_dir, "create_processes.sh")
        stop_file = os.path.join(self.tmp_dir, "create_processes.stop")
        AgentTestCase.create_script(test_script, """
#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 <output_file> <count>"
    exit 1
fi

echo $$ >> $1

if [[ $2 > 1 ]]; then
    $0 $1 $(($2 - 1))
else
    timeout 30s /usr/bin/env bash -c "while ! [[ -f {0} ]]; do sleep 0.25s; done"
fi

exit 0
""".format(stop_file))

        number_of_descendants = 3

        def wait_for_processes(processes_file):
            def _all_present():
                if os.path.exists(processes_file):
                    with open(processes_file, "r") as file_stream:
                        _all_present.processes = [int(process) for process in file_stream.read().split()]
                return len(_all_present.processes) >= number_of_descendants
            _all_present.processes = []

            if not wait_for(_all_present):
                raise Exception("Timeout waiting for processes. Expected {0}; got: {1}".format(
                    number_of_descendants, format_processes(_all_present.processes)))

            return _all_present.processes

        threads = []

        try:
            #
            # Start the processes that will be used by the test. We use two sets of processes: the first set simulates a command executed by the agent
            # (e.g. iptables) and its child processes, if any. The second set of processes simulates an extension.
            #
            agent_command_output = os.path.join(self.tmp_dir, "agent_command.pids")
            agent_command = threading.Thread(target=lambda: shellutil.run_command([test_script, agent_command_output, str(number_of_descendants)]))
            agent_command.start()
            threads.append(agent_command)
            agent_command_processes = wait_for_processes(agent_command_output)

            extension_output = os.path.join(self.tmp_dir, "extension.pids")

            def start_extension():
                original_sleep = time.sleep
                original_popen = subprocess.Popen

                # Extensions are stated using systemd-run; mock Popen to remove the call to systemd-run; the test script creates a couple of
                # child processes, which would simulate the extension's processes.
                def mock_popen(command, *args, **kwargs):
                    match = re.match(r"^systemd-run --unit=[^\s]+ --scope (.+)", command)
                    is_systemd_run = match is not None
                    if is_systemd_run:
                        command = match.group(1)
                    process = original_popen(command, *args, **kwargs)
                    if is_systemd_run:
                        start_extension.systemd_run_pid = process.pid
                    return process

                with patch('time.sleep', side_effect=lambda _: original_sleep(0.1)):  # start_extension_command has a small delay; skip it
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
                            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                                configurator.start_extension_command(
                                    extension_name="TestExtension",
                                    command="{0} {1} {2}".format(test_script, extension_output, number_of_descendants),
                                    timeout=30,
                                    shell=True,
                                    cwd=self.tmp_dir,
                                    env={},
                                    stdout=stdout,
                                    stderr=stderr)
            start_extension.systemd_run_pid = None

            extension = threading.Thread(target=start_extension)
            extension.start()
            threads.append(extension)
            extension_processes = wait_for_processes(extension_output)

            #
            # check_processes_in_agent_cgroup uses shellutil and the cgroups api to get the commands that are currently running;
            # wait for all the processes to show up
            #
            # protected-access: Access to a protected member _cgroups_api of a client class - Disabled: OK to access protected member in this unit test
            if not wait_for(lambda: len(shellutil.get_running_commands()) > 0 and len(configurator._cgroups_api.get_systemd_run_commands()) > 0):  # pylint:disable=protected-access
                raise Exception("Timeout while attempting to track the child commands")

            #
            # Verify that check_processes_in_agent_cgroup raises when there are unexpected processes in the agent's cgroup.
            #
            # For the agent's processes, we use the current process and its parent (in the actual agent these would be the daemon and the extension
            # handler), and the commands started by the agent.
            #
            # For other processes, we use process 1, a process that already completed, and an extension. Note that extensions are started using
            # systemd-run and the process for that commands belongs to the agent's cgroup but the processes for the extension should be in a
            # different cgroup
            #
            def get_completed_process():
                random.seed()
                completed = random.randint(1000, 10000)
                while os.path.exists("/proc/{0}".format(completed)):  # ensure we do not use an existing process
                    completed = random.randint(1000, 10000)
                return completed

            agent_processes = [os.getppid(), os.getpid()] + agent_command_processes + [start_extension.systemd_run_pid]
            other_processes = [1, get_completed_process()] + extension_processes

            with patch("azurelinuxagent.common.cgroupconfigurator.CGroupsApi.get_processes_in_cgroup", return_value=agent_processes + other_processes):
                with self.assertRaises(UnexpectedProcessesInCGroupException) as context_manager:
                    CGroupConfigurator.get_instance().check_processes_in_agent_cgroup()

                reported = context_manager.exception.unexpected

                self.assertEqual(
                    len(other_processes), len(reported),
                    "An incorrect number of processes was reported. Expected: {0} Got: {1}".format(format_processes(other_processes), reported))
                for pid in other_processes:
                    self.assertTrue(
                        any(reported_process.startswith("[PID: {0}]".format(pid)) for reported_process in reported),
                        "Process {0} was not reported. Got: {1}".format(format_processes([pid]), reported))

            #
            # And now verify that it does not raise when only the expected processes are in the cgroup
            #
            error = None
            try:
                with patch("azurelinuxagent.common.cgroupconfigurator.CGroupsApi.get_processes_in_cgroup", return_value=agent_processes):
                    CGroupConfigurator.get_instance().check_processes_in_agent_cgroup()
            except UnexpectedProcessesInCGroupException as exception:
                error = exception
            # we fail outside the except clause, otherwise the failure is reported as "During handling of the above exception, another exception occurred:..."
            if error is not None:
                self.fail("The check of the agent's cgroup should not have reported errors. Reported processes: {0}".format(error.unexpected))

        finally:
            # create the file that stops the test process and wait for them to complete
            open(stop_file, "w").close()
            for thread in threads:
                thread.join(timeout=5)


