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
from azurelinuxagent.common.cgroupapi import CGroupsApi, FileSystemCgroupsApi, SystemdCgroupsApi, CGROUPS_FILE_SYSTEM_ROOT, VM_AGENT_CGROUP_NAME
from azurelinuxagent.common.exception import CGroupsException, ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil, fileutil
from nose.plugins.attrib import attr
from tests.utils.cgroups_tools import CGroupsTools
from tests.tools import AgentTestCase, patch, skip_if_predicate_false, is_systemd_present, i_am_root, mock_sleep


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
    def test_create_should_return_a_SystemdCgroupsApi_on_systemd_platforms(self):
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=True):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == SystemdCgroupsApi)

    def test_create_should_return_a_FileSystemCgroupsApi_on_non_systemd_platforms(self):
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == FileSystemCgroupsApi)

    def test_is_systemd_should_return_true_when_systemd_manages_current_process(self):
        path_exists = os.path.exists

        def mock_path_exists(path):
            if path == "/run/systemd/system/":
                mock_path_exists.path_tested = True
                return True
            return path_exists(path)

        mock_path_exists.path_tested = False

        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", mock_path_exists):
            is_systemd = CGroupsApi._is_systemd()

        self.assertTrue(is_systemd)

        self.assertTrue(mock_path_exists.path_tested, 'The expected path was not tested; the implementation of CGroupsApi._is_systemd() may have changed.')

    def test_is_systemd_should_return_false_when_systemd_does_not_manage_current_process(self):
        path_exists = os.path.exists

        def mock_path_exists(path):
            if path == "/run/systemd/system/":
                mock_path_exists.path_tested = True
                return False
            return path_exists(path)

        mock_path_exists.path_tested = False

        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", mock_path_exists):
            is_systemd = CGroupsApi._is_systemd()

        self.assertFalse(is_systemd)

        self.assertTrue(mock_path_exists.path_tested, 'The expected path was not tested; the implementation of CGroupsApi._is_systemd() may have changed.')

    def test_foreach_controller_should_execute_operation_on_all_mounted_controllers(self):
        executed_controllers = []

        def controller_operation(controller):
            executed_controllers.append(controller)

        CGroupsApi._foreach_controller(controller_operation, 'A dummy message')

        # The setUp method mocks azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT to have the cpu and memory controllers mounted
        self.assertIn('cpu', executed_controllers, 'The operation was not executed on the cpu controller')
        self.assertIn('memory', executed_controllers, 'The operation was not executed on the memory controller')
        self.assertEqual(len(executed_controllers), 2, 'The operation was not executed on unexpected controllers: {0}'.format(executed_controllers))

    def test_foreach_controller_should_handle_errors_in_individual_controllers(self):
        successful_controllers = []

        def controller_operation(controller):
            if controller == 'cpu':
                raise Exception('A test exception')

            successful_controllers.append(controller)

        with patch("azurelinuxagent.common.cgroupapi.logger.warn") as mock_logger_warn:
            CGroupsApi._foreach_controller(controller_operation, 'A dummy message')

            self.assertIn('memory', successful_controllers, 'The operation was not executed on the memory controller')
            self.assertEqual(len(successful_controllers), 1, 'The operation was not executed on unexpected controllers: {0}'.format(successful_controllers))

            args, kwargs = mock_logger_warn.call_args
            (message_format, controller, error, message) = args
            self.assertEquals(message_format, 'Error in cgroup controller "{0}": {1}. {2}')
            self.assertEquals(controller, 'cpu')
            self.assertEquals(error, 'A test exception')
            self.assertEquals(message, 'A dummy message')


class FileSystemCgroupsApiTestCase(_MockedFileSystemTestCase):
    def test_cleanup_legacy_cgroups_should_move_daemon_pid_to_new_cgroup_and_remove_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid = "42"
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, daemon_pid + "\n")

        # Set up old controller cgroups and add the daemon PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", daemon_pid)
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", daemon_pid)

        # Set up new controller cgroups and add extension handler's PID to them
        new_cpu_cgroup = CGroupsTools.create_agent_cgroup(self.cgroups_file_system_root, "cpu", "999")
        new_memory_cgroup = CGroupsTools.create_agent_cgroup(self.cgroups_file_system_root, "memory", "999")

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
                FileSystemCgroupsApi().cleanup_legacy_cgroups()

        # The method should have added the daemon PID to the new controllers and deleted the old ones
        new_cpu_contents = fileutil.read_file(os.path.join(new_cpu_cgroup, "cgroup.procs"))
        new_memory_contents = fileutil.read_file(os.path.join(new_memory_cgroup, "cgroup.procs"))

        self.assertTrue(daemon_pid in new_cpu_contents)
        self.assertTrue(daemon_pid in new_memory_contents)

        self.assertFalse(os.path.exists(legacy_cpu_cgroup))
        self.assertFalse(os.path.exists(legacy_memory_cgroup))

        # Assert the event parameters that were sent out
        self.assertEquals(len(mock_add_event.call_args_list), 2)
        self.assertTrue(all(kwargs['op'] == 'CGroupsCleanUp' for _, kwargs in mock_add_event.call_args_list))
        self.assertTrue(all(kwargs['is_success'] for _, kwargs in mock_add_event.call_args_list))
        self.assertTrue(any(
            re.match(r"Moved daemon's PID from legacy cgroup to /.*/cgroup/cpu/walinuxagent.service", kwargs['message'])
            for _, kwargs in mock_add_event.call_args_list))
        self.assertTrue(any(
            re.match(r"Moved daemon's PID from legacy cgroup to /.*/cgroup/memory/walinuxagent.service", kwargs['message'])
            for _, kwargs in mock_add_event.call_args_list))

    def test_create_agent_cgroups_should_create_cgroups_on_all_controllers(self):
        agent_cgroups = FileSystemCgroupsApi().create_agent_cgroups()

        def assert_cgroup_created(controller):
            cgroup_path = os.path.join(self.cgroups_file_system_root, controller, VM_AGENT_CGROUP_NAME)
            self.assertTrue(any(cgroups.path == cgroup_path for cgroups in agent_cgroups))
            self.assertTrue(any(cgroups.name == VM_AGENT_CGROUP_NAME for cgroups in agent_cgroups))
            self.assertTrue(os.path.exists(cgroup_path))
            cgroup_task = int(fileutil.read_file(os.path.join(cgroup_path, "cgroup.procs")))
            current_process = os.getpid()
            self.assertEqual(cgroup_task, current_process)

        assert_cgroup_created("cpu")
        assert_cgroup_created("memory")

    def test_create_extension_cgroups_root_should_create_root_directory_for_extensions(self):
        FileSystemCgroupsApi().create_extension_cgroups_root()

        cpu_cgroup = os.path.join(self.cgroups_file_system_root, "cpu", "walinuxagent.extensions")
        self.assertTrue(os.path.exists(cpu_cgroup))

        memory_cgroup = os.path.join(self.cgroups_file_system_root, "memory", "walinuxagent.extensions")
        self.assertTrue(os.path.exists(memory_cgroup))

    def test_create_extension_cgroups_should_create_cgroups_on_all_controllers(self):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()
        extension_cgroups = api.create_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        def assert_cgroup_created(controller):
            cgroup_path = os.path.join(self.cgroups_file_system_root, controller, "walinuxagent.extensions",
                                       "Microsoft.Compute.TestExtension_1.2.3")

            self.assertTrue(any(cgroups.path == cgroup_path for cgroups in extension_cgroups))
            self.assertTrue(os.path.exists(cgroup_path))

        assert_cgroup_created("cpu")
        assert_cgroup_created("memory")

    def test_remove_extension_cgroups_should_remove_all_cgroups(self):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()
        extension_cgroups = api.create_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        api.remove_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        for cgroup in extension_cgroups:
            self.assertFalse(os.path.exists(cgroup.path))

    def test_remove_extension_cgroups_should_log_a_warning_when_the_cgroup_contains_active_tasks(self):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()
        api.create_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        with patch("azurelinuxagent.common.cgroupapi.logger.warn") as mock_logger_warn:
            with patch("azurelinuxagent.common.cgroupapi.os.rmdir", side_effect=OSError(16, "Device or resource busy")):
                api.remove_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

            args, kwargs = mock_logger_warn.call_args
            message = args[0]
            self.assertIn("still has active tasks", message)

    def test_get_extension_cgroups_should_return_all_cgroups(self):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()
        created = api.create_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        retrieved = api.get_extension_cgroups("Microsoft.Compute.TestExtension-1.2.3")

        self.assertEqual(len(retrieved), len(created))

        for cgroup in created:
            self.assertTrue(any(retrieved_cgroup.path == cgroup.path for retrieved_cgroup in retrieved))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_add_the_child_process_to_the_extension_cgroup(self, _):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                extension_cgroups, process_output = api.start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="echo $$",
                    timeout=300,
                    shell=True,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=stdout,
                    stderr=stderr)

        # The expected format of the process output is [stdout]\n{PID}\n\n\n[stderr]\n"
        pattern = re.compile(r"\[stdout\]\n(\d+)\n\n\n\[stderr\]\n")
        m = pattern.match(process_output)

        try:
            pid_from_output = int(m.group(1))
        except Exception as e:
            self.fail("No PID could be extracted from the process output! Error: {0}".format(ustr(e)))

        for cgroup in extension_cgroups:
            cgroups_procs_path = os.path.join(cgroup.path, "cgroup.procs")
            with open(cgroups_procs_path, "r") as f:
                contents = f.read()
            pid_from_cgroup = int(contents)

            self.assertEquals(pid_from_output, pid_from_cgroup,
                              "The PID from the process output ({0}) does not match the PID found in the"
                              "process cgroup {1} ({2})".format(pid_from_output, cgroups_procs_path, pid_from_cgroup))


@skip_if_predicate_false(is_systemd_present, "Systemd cgroups API doesn't manage cgroups on systems not using systemd.")
class SystemdCgroupsApiTestCase(AgentTestCase):
    def test_get_extensions_slice_root_name_should_return_the_root_slice_for_extensions(self):
        root_slice_name = SystemdCgroupsApi()._get_extensions_slice_root_name()
        self.assertEqual(root_slice_name, "system-walinuxagent.extensions.slice")

    def test_get_extension_slice_name_should_return_the_slice_for_the_given_extension(self):
        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        extension_slice_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name)
        self.assertEqual(extension_slice_name, "system-walinuxagent.extensions-Microsoft.Azure.DummyExtension_1.0.slice")

    @attr('requires_sudo')
    def test_create_extension_cgroups_root_should_create_extensions_root_slice(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        SystemdCgroupsApi().create_extension_cgroups_root()

        unit_name = SystemdCgroupsApi()._get_extensions_slice_root_name()
        _, status = shellutil.run_get_output("systemctl status {0}".format(unit_name))
        self.assertIn("Loaded: loaded", status)
        self.assertIn("Active: active", status)

        shellutil.run_get_output("systemctl stop {0}".format(unit_name))
        shellutil.run_get_output("systemctl disable {0}".format(unit_name))
        os.remove("/etc/systemd/system/{0}".format(unit_name))
        shellutil.run_get_output("systemctl daemon-reload")

    @attr('requires_sudo')
    def test_create_extension_cgroups_should_create_extension_slice(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        cgroups = SystemdCgroupsApi().create_extension_cgroups(extension_name)
        cpu_cgroup, memory_cgroup = cgroups[0], cgroups[1]
        self.assertEqual(cpu_cgroup.path, "/sys/fs/cgroup/cpu/system.slice/Microsoft.Azure.DummyExtension_1.0")
        self.assertEqual(memory_cgroup.path, "/sys/fs/cgroup/memory/system.slice/Microsoft.Azure.DummyExtension_1.0")

        unit_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name)
        self.assertEqual("system-walinuxagent.extensions-Microsoft.Azure.DummyExtension_1.0.slice", unit_name)

        _, status = shellutil.run_get_output("systemctl status {0}".format(unit_name))
        self.assertIn("Loaded: loaded", status)
        self.assertIn("Active: active", status)

        shellutil.run_get_output("systemctl stop {0}".format(unit_name))
        shellutil.run_get_output("systemctl disable {0}".format(unit_name))
        os.remove("/etc/systemd/system/{0}".format(unit_name))
        shellutil.run_get_output("systemctl daemon-reload")

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
    def test_start_extension_command_should_create_extension_scopes(self, _):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            return original_popen("date", **kwargs)

        # we mock subprocess.Popen to execute a dummy command (date), so no actual cgroups are created; their paths
        # should be computed properly, though
        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", mock_popen):
            extension_cgroups, process_output = SystemdCgroupsApi().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="date",
                shell=False,
                timeout=300,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            self.assert_cgroups_created(extension_cgroups)

    @attr('requires_sudo')
    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.2))
    def test_start_extension_command_should_use_systemd_and_not_the_fallback_option_if_successful(self, _):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) \
                        as patch_mock_popen:
                    extension_cgroups, process_output = SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="date",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    # We should have invoked the extension command only once and succeeded
                    self.assertEquals(1, patch_mock_popen.call_count)

                    args = patch_mock_popen.call_args[0][0]
                    self.assertIn("systemd-run --unit", args)

                    self.assert_cgroups_created(extension_cgroups)

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.2))
    def test_start_extension_command_should_use_fallback_option_if_systemd_fails(self, _):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Inject a syntax error to the call
            systemd_command = args[0].replace('systemd-run', 'systemd-run syntax_error')
            new_args = (systemd_command,)
            return original_popen(new_args, **kwargs)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) \
                            as patch_mock_popen:
                        # We expect this call to fail because of the syntax error
                        extension_cgroups, process_output = SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="date",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        args, kwargs = mock_add_event.call_args
                        self.assertIn("Failed to run systemd-run for unit Microsoft.Compute.TestExtension_1.2.3",
                                      kwargs['message'])
                        self.assertIn("Failed to find executable syntax_error: No such file or directory",
                                      kwargs['message'])
                        self.assertEquals(False, kwargs['is_success'])
                        self.assertEquals('InvokeCommandUsingSystemd', kwargs['op'])

                        # We expect two calls to Popen, first for the systemd-run call, second for the fallback option
                        self.assertEquals(2, patch_mock_popen.call_count)

                        first_call_args = patch_mock_popen.mock_calls[0][1][0]
                        second_call_args = patch_mock_popen.mock_calls[1][1][0]
                        self.assertIn("systemd-run --unit", first_call_args)
                        self.assertNotIn("systemd-run --unit", second_call_args)

                        # No cgroups should have been created
                        self.assertEquals(extension_cgroups, [])

    @patch('time.sleep', side_effect=lambda _: mock_sleep(0.001))
    def test_start_extension_command_should_use_fallback_option_if_systemd_times_out(self, _):
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

        expected_output = "[stdout]\n{0}\n\n\n[stderr]\n"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) \
                        as patch_mock_popen:
                    extension_cgroups, process_output = SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="echo 'success'",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    # We expect two calls to Popen, first for the systemd-run call, second for the fallback option
                    self.assertEquals(2, patch_mock_popen.call_count)

                    first_call_args = patch_mock_popen.mock_calls[0][1][0]
                    second_call_args = patch_mock_popen.mock_calls[1][1][0]
                    self.assertIn("systemd-run --unit", first_call_args)
                    self.assertNotIn("systemd-run --unit", second_call_args)

                    self.assertEquals(extension_cgroups, [])
                    self.assertEquals(expected_output.format("success"), process_output)

    @attr('requires_sudo')
    @patch("azurelinuxagent.common.cgroupapi.add_event")
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) \
                        as patch_mock_popen:
                    with self.assertRaises(ExtensionError) as context_manager:
                        SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="ls folder_does_not_exist",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        # We should have invoked the extension command only once, in the systemd-run case
                        self.assertEquals(1, patch_mock_popen.call_count)
                        args = patch_mock_popen.call_args[0][0]
                        self.assertIn("systemd-run --unit", args)

                        self.assertEquals(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                        self.assertIn("Non-zero exit code", ustr(context_manager.exception))

    @attr('requires_sudo')
    @patch("azurelinuxagent.common.cgroupapi.add_event")
    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args):
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

                        self.assertEquals(context_manager.exception.code,
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
                        extension_cgroups, process_output = SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="echo 'very specific test message'",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        self.assertEquals(expected_output.format("very specific test message"), process_output)
                        self.assertEquals(extension_cgroups, [])

    @patch("azurelinuxagent.common.utils.fileutil.read_file")
    def test_create_agent_cgroups_should_create_cgroups_on_all_controllers(self, patch_read_file):
        mock_proc_self_cgroup = '''12:blkio:/system.slice/walinuxagent.service
11:memory:/system.slice/walinuxagent.service
10:perf_event:/
9:hugetlb:/
8:freezer:/
7:net_cls,net_prio:/
6:devices:/system.slice/walinuxagent.service
5:cpuset:/
4:cpu,cpuacct:/system.slice/walinuxagent.service
3:pids:/system.slice/walinuxagent.service
2:rdma:/
1:name=systemd:/system.slice/walinuxagent.service
0::/system.slice/walinuxagent.service
'''
        patch_read_file.return_value = mock_proc_self_cgroup
        agent_cgroups = SystemdCgroupsApi().create_agent_cgroups()

        def assert_cgroup_created(controller):
            expected_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, "system.slice", VM_AGENT_CGROUP_NAME)

            self.assertTrue(any(cgroups.path == expected_cgroup_path for cgroups in agent_cgroups))
            self.assertTrue(any(cgroups.name == VM_AGENT_CGROUP_NAME for cgroups in agent_cgroups))

        assert_cgroup_created("cpu")
        assert_cgroup_created("memory")


class SystemdCgroupsApiMockedFileSystemTestCase(_MockedFileSystemTestCase):
    def test_cleanup_legacy_cgroups_should_remove_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, "42\n")

        # Set up old controller cgroups, but do not add the daemon's PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", '')
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", '')

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
                    SystemdCgroupsApi().cleanup_legacy_cgroups()

        self.assertFalse(os.path.exists(legacy_cpu_cgroup))
        self.assertFalse(os.path.exists(legacy_memory_cgroup))

    def test_cleanup_legacy_cgroups_should_report_an_error_when_the_daemon_pid_was_added_to_the_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid = "42"
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, daemon_pid + "\n")

        # Set up old controller cgroups and add the daemon's PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", daemon_pid)
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", daemon_pid)

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
                with self.assertRaises(CGroupsException) as context_manager:
                    SystemdCgroupsApi().cleanup_legacy_cgroups()

        self.assertEquals(str(context_manager.exception), "[CGroupsException] The daemon's PID ({0}) was already added to the legacy cgroup; this invalidates resource usage data.".format(daemon_pid))

        # The method should have deleted the legacy cgroups
        self.assertFalse(os.path.exists(legacy_cpu_cgroup))
        self.assertFalse(os.path.exists(legacy_memory_cgroup))

