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
import re
import subprocess
import tempfile

from nose.plugins.attrib import attr

from azurelinuxagent.common.cgroupapi import CGroupsApi, SystemdCgroupsApi, SYSTEMD_RUN_PATH
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil
from tests.common.mock_cgroup_commands import mock_cgroup_commands
from tests.tools import AgentTestCase, patch, skip_if_predicate_false, is_systemd_present, i_am_root, mock_sleep
from tests.utils.cgroups_tools import CGroupsTools


class _MockedFileSystemTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

        self.mock_cgroups_file_system_root = patch("azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock_cgroups_file_system_root.start()

    def tearDown(self):
        self.mock_cgroups_file_system_root.stop()
        AgentTestCase.tearDown(self)


class CGroupsApiTestCase(_MockedFileSystemTestCase):
    def test_cgroups_should_be_supported_only_on_ubuntu_16_and_later(self):
        test_cases = [
            (['ubuntu', '16.04', 'xenial'], True),
            (['ubuntu', '16.10', 'yakkety'], True),
            (['ubuntu', '18.04', 'bionic'], True),
            (['ubuntu', '18.10', 'cosmic'], True),
            (['ubuntu', '20.04', 'focal'], True),
            (['ubuntu', '20.10', 'groovy'], True),
            (['centos', '7.5', 'Source'], False),
            (['redhat', '7.7', 'Maipo'], False),
            (['redhat', '7.7.1908', 'Core'], False),
            (['bigip', '15.0.1', 'Final'], False),
            (['gaia', '273.562', 'R80.30'], False),
            (['debian', '9.1', ''], False),
        ]

        for (distro, supported) in test_cases:
            with patch("azurelinuxagent.common.cgroupapi.get_distro", return_value=distro):
                self.assertEqual(CGroupsApi.cgroups_supported(), supported, "cgroups_supported() failed on {0}".format(distro))

    def test_is_systemd_should_return_true_when_systemd_manages_current_process(self):
        path_exists = os.path.exists

        def mock_path_exists(path):
            if path == SYSTEMD_RUN_PATH:
                mock_path_exists.path_tested = True
                return True
            return path_exists(path)

        mock_path_exists.path_tested = False

        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", mock_path_exists):
            is_systemd = CGroupsApi.is_systemd()  # pylint: disable=protected-access

        self.assertTrue(is_systemd)

        self.assertTrue(mock_path_exists.path_tested, 'The expected path was not tested; the implementation of CGroupsApi._is_systemd() may have changed.')

    def test_is_systemd_should_return_false_when_systemd_does_not_manage_current_process(self):
        path_exists = os.path.exists

        def mock_path_exists(path):
            if path == SYSTEMD_RUN_PATH:
                mock_path_exists.path_tested = True
                return False
            return path_exists(path)

        mock_path_exists.path_tested = False

        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", mock_path_exists):
            is_systemd = CGroupsApi.is_systemd()  # pylint: disable=protected-access

        self.assertFalse(is_systemd)

        self.assertTrue(mock_path_exists.path_tested, 'The expected path was not tested; the implementation of CGroupsApi._is_systemd() may have changed.')


@skip_if_predicate_false(is_systemd_present, "Systemd cgroups API doesn't manage cgroups on systems not using systemd.")
class SystemdCgroupsApiTestCase(AgentTestCase):
    def test_get_systemd_version_should_return_a_version_number(self):
        with mock_cgroup_commands():
            version_info = SystemdCgroupsApi.get_systemd_version()
            found = re.search(r"systemd \d+", version_info) is not None
            self.assertTrue(found, "Could not determine the systemd version: {0}".format(version_info))

    def test_get_cpu_and_memory_mount_points_should_return_the_cgroup_mount_points(self):
        with mock_cgroup_commands():
            cpu, memory = SystemdCgroupsApi().get_cgroup_mount_points()
            self.assertEqual(cpu, '/sys/fs/cgroup/cpu,cpuacct', "The mount point for the CPU controller is incorrect")
            self.assertEqual(memory, '/sys/fs/cgroup/memory', "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_relative_paths(self):
        with mock_cgroup_commands():
            cpu, memory = SystemdCgroupsApi.get_process_cgroup_relative_paths('self')
            self.assertEqual(cpu, "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEqual(memory, "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")

    def test_get_cgroup2_controllers_should_return_the_v2_cgroup_controllers(self):
        with mock_cgroup_commands():
            mount_point, controllers = SystemdCgroupsApi.get_cgroup2_controllers()

            self.assertEqual(mount_point, "/sys/fs/cgroup/unified", "Invalid mount point for V2 cgroups")
            self.assertIn("cpu", controllers, "The CPU controller is not in the list of V2 controllers")
            self.assertIn("memory", controllers, "The memory controller is not in the list of V2 controllers")

    def test_get_unit_property_should_return_the_value_of_the_given_property(self):
        with mock_cgroup_commands():
            cpu_accounting = SystemdCgroupsApi.get_unit_property("walinuxagent.service", "CPUAccounting")

            self.assertEqual(cpu_accounting, "no", "Property {0} of {1} is incorrect".format("CPUAccounting", "walinuxagent.service"))

    def test_get_extensions_slice_root_name_should_return_the_root_slice_for_extensions(self):
        root_slice_name = SystemdCgroupsApi()._get_extensions_root_slice_name()  # pylint: disable=protected-access
        self.assertEqual(root_slice_name, "azure-vmextensions.slice")

    def test_get_extension_slice_name_should_return_the_slice_for_the_given_extension(self):
        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        extension_slice_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name)  # pylint: disable=protected-access
        self.assertEqual(extension_slice_name, "azure-vmextensions-Microsoft.Azure.DummyExtension_1.0.slice")

    def test_create_azure_slice_should_create_unit_file(self):
        azure_slice_path = os.path.join(self.tmp_dir, "azure.slice")
        self.assertFalse(os.path.exists(azure_slice_path))

        with mock_cgroup_commands() as mocks:
            # Mock out the actual calls to /etc/systemd
            mocks.add_file(r"^/etc/systemd/system/azure.slice$", azure_slice_path)
            SystemdCgroupsApi().create_azure_slice()

        self.assertTrue(os.path.exists(azure_slice_path))

    def test_create_extensions_slice_should_create_unit_file(self):
        extensions_slice_path = os.path.join(self.tmp_dir, "azure-vmextensions.slice")
        self.assertFalse(os.path.exists(extensions_slice_path))

        with mock_cgroup_commands() as mocks:
            # Mock out the actual calls to /etc/systemd
            mocks.add_file(r"^/etc/systemd/system/azure-vmextensions.slice$", extensions_slice_path)
            SystemdCgroupsApi().create_extensions_slice()

        self.assertTrue(os.path.exists(extensions_slice_path))

    def assert_cgroups_created(self, extension_cgroups):
        self.assertEqual(len(extension_cgroups), 2,
                         'start_extension_command did not return the expected number of cgroups')

        cpu_found = memory_found = False

        for cgroup in extension_cgroups:
            match = re.match(
                r'^/sys/fs/cgroup/(cpu|memory)/system.slice/Microsoft.Compute.TestExtension_1\.2\.3\_([a-f0-9-]+)\.scope$',
                cgroup.path)

            self.assertTrue(match is not None, "Unexpected path for cgroup: {0}".format(cgroup.path))

            if match.group(1) == 'cpu':
                cpu_found = True
            if match.group(1) == 'memory':
                memory_found = True

        self.assertTrue(cpu_found, 'start_extension_command did not return a cpu cgroup')
        self.assertTrue(memory_found, 'start_extension_command did not return a memory cgroup')

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_return_the_command_output(self, _):
        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            if command.startswith('systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3'):
                command = "echo TEST_OUTPUT"
            return original_popen(command, *args, **kwargs)

        with mock_cgroup_commands() as mock_commands:  # pylint: disable=unused-variable
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch:  # pylint: disable=unused-variable
                    command_output = SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="A_TEST_COMMAND",
                        shell=True,
                        timeout=300,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=output_file,
                        stderr=output_file)

                    self.assertIn("[stdout]\nTEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_execute_the_command_in_a_cgroup(self, _):
        with mock_cgroup_commands():
            SystemdCgroupsApi().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                shell=False,
                timeout=300,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            tracked = CGroupsTelemetry._tracked  # pylint: disable=protected-access

            self.assertTrue(
                any(cg for cg in tracked if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
                "The extension's CPU is not being tracked")
            self.assertTrue(
                any(cg for cg in tracked if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'memory' in cg.path),
                "The extension's memory is not being tracked")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_use_systemd_to_execute_the_command(self, _):
        with mock_cgroup_commands():
            with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                SystemdCgroupsApi().start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    timeout=300,
                    shell=True,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if "the-test-extension-command" in args[0]]

                self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0], "The extension should have been invoked using systemd")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_invoke_the_command_directly_if_systemd_fails(self, _):
        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            if command.startswith('systemd-run'):
                # Inject a syntax error to the call
                command = command.replace('systemd-run', 'systemd-run syntax_error')
            return original_popen(command, *args, **kwargs)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
            with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch:
                    CGroupsTelemetry.reset()

                    command = "echo TEST_OUTPUT"

                    command_output = SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command=command,
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=output_file,
                        stderr=output_file)

                    args, kwargs = mock_add_event.call_args
                    self.assertIn("Failed to run systemd-run for unit Microsoft.Compute.TestExtension_1.2.3",
                                  kwargs['message'])
                    self.assertIn("Failed to find executable syntax_error: No such file or directory",
                                  kwargs['message'])
                    self.assertEqual(False, kwargs['is_success'])
                    self.assertEqual('InvokeCommandUsingSystemd', kwargs['op'])

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                    self.assertEqual(2, len(extension_calls), "The extension should have been invoked exactly twice")
                    self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0],
                                  "The first call to the extension should have used systemd")
                    self.assertEqual(command, extension_calls[1],
                                      "The second call to the extension should not have used systemd")

                    self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")  # pylint: disable=protected-access

                    self.assertIn("TEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_invoke_the_command_directly_if_systemd_times_out(self, _):
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

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch:
                    CGroupsTelemetry.reset()

                    SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="echo 'success'",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if "echo 'success'" in args[0]]

                    self.assertEqual(2, len(extension_calls), "The extension should have been invoked exactly twice")
                    self.assertIn("systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3", extension_calls[0], "The first call to the extension should have used systemd")
                    self.assertEqual("echo 'success'", extension_calls[1], "The second call to the extension should not have used systemd")

                    self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")  # pylint: disable=protected-access

    @attr('requires_sudo')
    @patch("azurelinuxagent.common.cgroupapi.add_event")
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        command = "ls folder_does_not_exist"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        SystemdCgroupsApi().start_extension_command(
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
    @patch("azurelinuxagent.common.cgroupapi.add_event")
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    @patch("azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN", 5)
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails_with_long_output(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        long_output = "a"*20  # large enough to ensure both stdout and stderr are truncated
        long_stdout_stderr_command = "echo {0} && echo {0} >&2 && ls folder_does_not_exist".format(long_output)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        SystemdCgroupsApi().start_extension_command(
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
    @patch("azurelinuxagent.common.cgroupapi.add_event")
    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args):  # pylint: disable=unused-argument
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.utils.extensionprocessutil.wait_for_process_completion_or_timeout",
                           return_value=[True, None]):
                    with patch("azurelinuxagent.common.cgroupapi.SystemdCgroupsApi._is_systemd_failure",
                               return_value=False):
                        with self.assertRaises(ExtensionError) as context_manager:
                            SystemdCgroupsApi().start_extension_command(
                                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                                command="date",
                                timeout=300,
                                shell=True,
                                cwd=self.tmp_dir,
                                env={},
                                stdout=stdout,
                                stderr=stderr)

                        self.assertEqual(context_manager.exception.code,
                                          ExtensionErrorCodes.PluginHandlerScriptTimedout)
                        self.assertIn("Timeout", ustr(context_manager.exception))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_capture_only_the_last_subprocess_output(self, _):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Inject a syntax error to the call
            systemd_command = args[0].replace('systemd-run', 'systemd-run syntax_error')
            new_args = (systemd_command,)
            return original_popen(new_args, **kwargs)

        expected_output = "[stdout]\n{0}\n\n\n[stderr]\n"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.add_event"):
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                        # We expect this call to fail because of the syntax error
                        process_output = SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="echo 'very specific test message'",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        self.assertEqual(expected_output.format("very specific test message"), process_output)


class SystemdCgroupsApiMockedFileSystemTestCase(_MockedFileSystemTestCase):
    def test_cleanup_legacy_cgroups_should_remove_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, "42\n")

        # Set up old controller cgroups, but do not add the daemon's PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", '')
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", '')

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:  # pylint: disable=unused-variable
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
                legacy_cgroups = SystemdCgroupsApi().cleanup_legacy_cgroups()

        self.assertEqual(legacy_cgroups, 2, "cleanup_legacy_cgroups() did not find all the expected cgroups")
        self.assertFalse(os.path.exists(legacy_cpu_cgroup), "cleanup_legacy_cgroups() did not remove the CPU legacy cgroup")
        self.assertFalse(os.path.exists(legacy_memory_cgroup), "cleanup_legacy_cgroups() did not remove the memory legacy cgroup")
