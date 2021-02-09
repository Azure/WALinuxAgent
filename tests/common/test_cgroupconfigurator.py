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

import contextlib
import os
import random
import re
import subprocess
import tempfile
import time
import threading

from nose.plugins.attrib import attr

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import CGroupsException, ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil
from tests.common.mock_cgroup_commands import mock_cgroup_commands, UnitFilePaths
from tests.tools import AgentTestCase, patch, mock_sleep, i_am_root, data_dir
from tests.utils.miscellaneous_tools import format_processes, wait_for


class CGroupConfiguratorSystemdTestCase(AgentTestCase):
    @classmethod
    def tearDownClass(cls):
        CGroupConfigurator._instance = None
        AgentTestCase.tearDownClass()

    @contextlib.contextmanager
    def _get_cgroup_configurator(self, initialize=True, command_mocks=None):
        CGroupConfigurator._instance = None
        configurator = CGroupConfigurator.get_instance()
        CGroupsTelemetry.reset()
        with mock_cgroup_commands(self.tmp_dir) as mocks:
            if command_mocks is not None:
                for command in command_mocks:
                    mocks.add_command_mock(command[0], command[1])
            configurator.mocks = mocks
            if initialize:
                configurator.initialize()
            yield configurator

    def test_initialize_should_start_tracking_the_agent_cgroups(self):
        with self._get_cgroup_configurator() as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
            self.assertTrue(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'cpu' in cg.path),
                "The Agent's CPU is not being tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_start_tracking_other_controllers_when_one_is_not_present(self):
        command_mocks = [(
            r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
''')]
        with self._get_cgroup_configurator(command_mocks=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
            self.assertFalse(any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'memory' in cg.path),
                "The Agent's memory should not be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_is_the_cpu_and_memory_controllers_are_not_present(self):
        command_mocks = [(
r"^mount -t cgroup$",
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
''')]
        with self._get_cgroup_configurator(command_mocks=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
            self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_when_the_agent_is_not_in_the_system_slice(self):
        command_mocks = [(
r"^mount -t cgroup$",
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
''')]

        with self._get_cgroup_configurator(command_mocks=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
            self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_create_unit_files(self):
        with self._get_cgroup_configurator() as configurator:
            # get the paths to the mocked files
            azure_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.azure)
            extensions_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.vmextensions)
            agent_drop_in_file_slice = configurator.mocks.get_mapped_path(UnitFilePaths.slice)
            agent_drop_in_file_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_accounting)
            agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)

            # The mock creates the slice unit files; delete them
            os.remove(azure_slice_unit_file)
            os.remove(extensions_slice_unit_file)

            # The service file for the agent includes settings for the slice and cpu accounting, but not for cpu quota; initialize()
            # should not create drop in files for the first 2, but it should create one the cpu quota
            self.assertFalse(os.path.exists(azure_slice_unit_file), "{0} should not have been created".format(azure_slice_unit_file))
            self.assertFalse(os.path.exists(extensions_slice_unit_file), "{0} should not have been created".format(extensions_slice_unit_file))
            self.assertFalse(os.path.exists(agent_drop_in_file_slice), "{0} should not have been created".format(agent_drop_in_file_slice))
            self.assertFalse(os.path.exists(agent_drop_in_file_cpu_accounting), "{0} should not have been created".format(agent_drop_in_file_cpu_accounting))
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_quota), "{0} was not created".format(agent_drop_in_file_cpu_quota))

    def test_initialize_should_create_unit_files_when_the_agent_service_file_is_not_updated(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            # get the paths to the mocked files
            azure_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.azure)
            extensions_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.vmextensions)
            agent_drop_in_file_slice = configurator.mocks.get_mapped_path(UnitFilePaths.slice)
            agent_drop_in_file_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_accounting)
            agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)

            # The mock creates the service and slice unit files; replace the former and delete the latter
            configurator.mocks.add_data_file(os.path.join(data_dir, 'init', "walinuxagent.service.previous"), UnitFilePaths.walinuxagent)
            os.remove(azure_slice_unit_file)
            os.remove(extensions_slice_unit_file)

            configurator.initialize()

            # The older service file for the agent did not include settings for the slice and cpu parameters; in that case, initialize() should
            # create drop in files to set those properties
            self.assertTrue(os.path.exists(azure_slice_unit_file), "{0} was not created".format(azure_slice_unit_file))
            self.assertTrue(os.path.exists(extensions_slice_unit_file), "{0} was not created".format(extensions_slice_unit_file))
            self.assertTrue(os.path.exists(agent_drop_in_file_slice), "{0} was not created".format(agent_drop_in_file_slice))
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_accounting), "{0} was not created".format(agent_drop_in_file_cpu_accounting))
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_quota), "{0} was not created".format(agent_drop_in_file_cpu_quota))

    def test_enable_and_disable_should_change_the_enabled_state_of_cgroups(self):
        with self._get_cgroup_configurator() as configurator:
            self.assertTrue(configurator.enabled(), "CGroupConfigurator should be enabled by default")

            configurator.disable()
            self.assertFalse(configurator.enabled(), "disable() should disable the CGroupConfigurator")

            configurator.enable()
            self.assertTrue(configurator.enabled(), "enable() should enable the CGroupConfigurator")

    def test_enable_should_raise_cgroups_exception_when_cgroups_are_not_supported(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            with patch("azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported", return_value=False):
                configurator.initialize()

                with self.assertRaises(CGroupsException) as context_manager:
                    configurator.enable()
                self.assertIn("Attempted to enable cgroups, but they are not supported on the current platform", str(context_manager.exception))

    def test_disable_should_reset_tracked_cgroups(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            # Start tracking a couple of dummy cgroups
            CGroupsTelemetry.track_cgroup(CGroup("dummy", "/sys/fs/cgroup/memory/system.slice/dummy.service", "cpu"))
            CGroupsTelemetry.track_cgroup(CGroup("dummy", "/sys/fs/cgroup/memory/system.slice/dummy.service", "memory"))

            configurator.disable()

            self.assertEqual(len(CGroupsTelemetry._tracked), 0)


    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_systemd_when_cgroups_are_not_enabled(self, _):
        with self._get_cgroup_configurator() as configurator:
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
        with self._get_cgroup_configurator() as configurator:
            with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                configurator.start_extension_command(
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
        with self._get_cgroup_configurator() as configurator:
            configurator.start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                timeout=300,
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        tracked = CGroupsTelemetry._tracked

        self.assertTrue(
            any(cg for cg in tracked if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
            "The extension's CPU is not being tracked")

    def test_start_extension_command_should_raise_an_exception_when_the_command_cannot_be_started(self):
        with self._get_cgroup_configurator() as configurator:
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

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_disable_cgroups_and_invoke_the_command_directly_if_systemd_fails(self, _):
        with self._get_cgroup_configurator() as configurator:
            original_popen = subprocess.Popen

            def mock_popen(command, *args, **kwargs):
                if command.startswith('systemd-run'):
                    # Inject a syntax error to the call
                    command = command.replace('systemd-run', 'systemd-run syntax_error')
                return original_popen(command, *args, **kwargs)

            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("azurelinuxagent.common.cgroupconfigurator.add_event") as mock_add_event:
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch:
                        CGroupsTelemetry.reset()

                        command = "echo TEST_OUTPUT"

                        command_output = configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=command,
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=output_file,
                            stderr=output_file)

                        self.assertFalse(configurator.enabled(), "Cgroups should have been disabled")

                        args, kwargs = mock_add_event.call_args
                        self.assertIn("Failed to start extension Microsoft.Compute.TestExtension-1.2.3 using systemd-run.",
                                      kwargs['message'])
                        self.assertIn("Failed to find executable syntax_error: No such file or directory",
                                      kwargs['message'])
                        self.assertEqual(False, kwargs['is_success'])
                        self.assertEqual(WALAEventOperation.CGroupsDisabled, kwargs['op'])

                        extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                        self.assertEqual(2, len(extension_calls), "The extension should have been invoked exactly twice")
                        self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0],
                                      "The first call to the extension should have used systemd")
                        self.assertEqual(command, extension_calls[1],
                                          "The second call to the extension should not have used systemd")

                        self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")

                        self.assertIn("TEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_disable_cgroups_and_invoke_the_command_directly_if_systemd_times_out(self, _):
        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        # Systemd has its own internal timeout which is shorter than what we define for extension operation timeout.
        # When systemd times out, it will write a message to stderr and exit with exit code 1.
        # In that case, we will internally recognize the failure due to the non-zero exit code, not as a timeout.
        original_popen = subprocess.Popen
        systemd_timeout_command = "echo 'Failed to start transient scope unit: Connection timed out' >&2 && exit 1"

        def mock_popen(*args, **kwargs):
            # If trying to invoke systemd, mock what would happen if systemd timed out internally:
            # write failure to stderr and exit with exit code 1.
            new_args = args
            if "systemd-run" in args[0]:
                new_args = (systemd_timeout_command,)

            return original_popen(new_args, **kwargs)
        mock_popen.extension_calls = []

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch:
                    CGroupsTelemetry.reset()

                    configurator.start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="echo 'success'",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    self.assertFalse(configurator.enabled(), "Cgroups should have been disabled")

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if "echo 'success'" in args[0]]
                    self.assertEqual(2, len(extension_calls), "The extension should have been called twice. Got: {0}".format(extension_calls))
                    self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0], "The first call to the extension should have used systemd")
                    self.assertNotIn("systemd-run", extension_calls[1], "The second call to the extension should not have used systemd")

                    self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")

    @attr('requires_sudo')
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        command = "ls folder_does_not_exist"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=command,
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # The scope name should appear in the process output since systemd-run was invoked and stderr
                    # wasn't truncated.
                    self.assertIn("Microsoft.Compute.TestExtension_1.2.3", ustr(context_manager.exception))

    @attr('requires_sudo')
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    @patch("azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN", 5)
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails_with_long_output(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        long_output = "a"*20  # large enough to ensure both stdout and stderr are truncated
        long_stdout_stderr_command = "echo {0} && echo {0} >&2 && ls folder_does_not_exist".format(long_output)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=long_stdout_stderr_command,
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if long_stdout_stderr_command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # stdout and stderr should have been truncated, so the scope name doesn't appear in stderr
                    # even though systemd-run ran
                    self.assertNotIn("Microsoft.Compute.TestExtension_1.2.3", ustr(context_manager.exception))

    @attr('requires_sudo')
    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args):  # pylint: disable=unused-argument
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.utils.extensionprocessutil.wait_for_process_completion_or_timeout",
                           return_value=[True, None]):
                    with patch("azurelinuxagent.common.cgroupapi.SystemdCgroupsApi._is_systemd_failure",
                               return_value=False):
                        with self.assertRaises(ExtensionError) as context_manager:
                            configurator.start_extension_command(
                                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                                command="date",
                                timeout=300,
                                shell=True,
                                cwd=self.tmp_dir,
                                env={},
                                stdout=stdout,
                                stderr=stderr)

                        self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginHandlerScriptTimedout)
                        self.assertIn("Timeout", ustr(context_manager.exception))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_capture_only_the_last_subprocess_output(self, _):
        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Inject a syntax error to the call
            systemd_command = args[0].replace('systemd-run', 'systemd-run syntax_error')
            new_args = (systemd_command,)
            return original_popen(new_args, **kwargs)

        expected_output = "[stdout]\n{0}\n\n\n[stderr]\n"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                    # We expect this call to fail because of the syntax error
                    process_output = configurator.start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="echo 'very specific test message'",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    self.assertEqual(expected_output.format("very specific test message"), process_output)

    def test_check_processes_in_agent_cgroup_should_disable_cgroups_when_there_are_unexpected_processes_in_the_agent_cgroup(self):
        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

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
                    match = re.match(r"^systemd-run --unit=[^\s]+ --scope --slice=[^\s]+ (.+)", command)
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
            if not wait_for(lambda: len(shellutil.get_running_commands()) > 0 and len(configurator._cgroups_api.get_systemd_run_commands()) > 0):
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

            def get_telemetry_event_messages():
                return [kwargs["message"] for (_, kwargs) in add_event_patcher.call_args_list if "The agent's cgroup includes unexpected processes" in kwargs["message"]]

            agent_processes = [os.getppid(), os.getpid()] + agent_command_processes + [start_extension.systemd_run_pid]
            other_processes = [1, get_completed_process()] + extension_processes

            with patch("azurelinuxagent.common.cgroupconfigurator.CGroupsApi.get_processes_in_cgroup", return_value=agent_processes + other_processes):
                with patch("azurelinuxagent.common.cgroupconfigurator.add_event") as add_event_patcher:
                    cgroup_configurator = CGroupConfigurator.get_instance()

                    return_value = cgroup_configurator.check_processes_in_agent_cgroup()

                    self.assertFalse(return_value, "check_processes_in_agent_cgroup() should have failed")
                    self.assertFalse(cgroup_configurator.enabled(), "Cgroups should have been disabled")

                    messages = get_telemetry_event_messages()

                    self.assertEqual(1, len(messages), "Exactly 1 telemetry event should have been reported. Events: {0}".format(messages))

                    # The list of processes in the message is an array of strings: "['foo', ..., 'bar']"
                    search = re.search(r'\[(?P<processes>.+)\]', messages[0])
                    self.assertIsNotNone(search, "The event message is not in the expected format: {0}".format(messages[0]))
                    reported = search.group('processes').split(',')

                    self.assertEqual(
                        len(other_processes), len(reported),
                        "An incorrect number of processes was reported. Expected: {0} Got: {1}".format(format_processes(other_processes), reported))
                    for pid in other_processes:
                        self.assertTrue(
                            any("[PID: {0}]".format(pid) in reported_process for reported_process in reported),
                            "Process {0} was not reported. Got: {1}".format(format_processes([pid]), reported))

        finally:
            # create the file that stops the test process and wait for them to complete
            open(stop_file, "w").close()
            for thread in threads:
                thread.join(timeout=5)

