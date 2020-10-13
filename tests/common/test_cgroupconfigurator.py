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

import re
import subprocess

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import CGroupsException
from tests.common.mock_cgroup_commands import mock_cgroup_commands
from tests.tools import AgentTestCase, patch, mock_sleep


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
            [configurator.create_extension_cgroups_root,                     "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups_root"],
            [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups"],
            [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.remove_extension_cgroups"]
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
                [configurator.create_extension_cgroups_root,                     "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups_root"],
                [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups"],
                [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.remove_extension_cgroups"]
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

    def test_get_processes_in_agent_cgroup_should_return_the_processes_within_the_agent_cgroup(self):
        with mock_cgroup_commands():
            configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

            processes = configurator.get_processes_in_agent_cgroup()

            self.assertTrue(len(processes) >= 2,
                "The cgroup should contain at least 2 procceses (daemon and extension handler): [{0}]".format(processes))

            daemon_present = any("waagent -daemon" in command for (pid, command) in processes)
            self.assertTrue(daemon_present, "Could not find the daemon in the cgroup: [{0}]".format(processes))

            extension_handler_present = any(re.search(r"(WALinuxAgent-.+\.egg|waagent) -run-exthandlers", command) for (pid, command) in processes)
            self.assertTrue(extension_handler_present, "Could not find the extension handler in the cgroup: [{0}]".format(processes))

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

