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

from azurelinuxagent.common.cgroupapi import CGroupsApi, FileSystemCgroupsApi, SystemdCgroupsApi, VM_AGENT_CGROUP_NAME, \
    SYSTEMD_RUN_PATH
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil, fileutil
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

    def test_create_should_return_a_SystemdCgroupsApi_on_systemd_platforms(self): # pylint: disable=invalid-name
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd", return_value=True):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == SystemdCgroupsApi) # pylint: disable=unidiomatic-typecheck

    def test_create_should_return_a_FileSystemCgroupsApi_on_non_systemd_platforms(self): # pylint: disable=invalid-name
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd", return_value=False):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == FileSystemCgroupsApi) # pylint: disable=unidiomatic-typecheck

    def test_is_systemd_should_return_true_when_systemd_manages_current_process(self):
        path_exists = os.path.exists

        def mock_path_exists(path):
            if path == SYSTEMD_RUN_PATH:
                mock_path_exists.path_tested = True
                return True
            return path_exists(path)

        mock_path_exists.path_tested = False

        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", mock_path_exists):
            is_systemd = CGroupsApi.is_systemd() # pylint: disable=protected-access

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
            is_systemd = CGroupsApi.is_systemd() # pylint: disable=protected-access

        self.assertFalse(is_systemd)

        self.assertTrue(mock_path_exists.path_tested, 'The expected path was not tested; the implementation of CGroupsApi._is_systemd() may have changed.')

    def test_foreach_controller_should_execute_operation_on_all_mounted_controllers(self):
        executed_controllers = []

        def controller_operation(controller):
            executed_controllers.append(controller)

        CGroupsApi._foreach_controller(controller_operation, 'A dummy message') # pylint: disable=protected-access

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
            CGroupsApi._foreach_controller(controller_operation, 'A dummy message') # pylint: disable=protected-access

            self.assertIn('memory', successful_controllers, 'The operation was not executed on the memory controller')
            self.assertEqual(len(successful_controllers), 1, 'The operation was not executed on unexpected controllers: {0}'.format(successful_controllers))

            args, kwargs = mock_logger_warn.call_args # pylint: disable=unused-variable
            (message_format, controller, error, message) = args
            self.assertEqual(message_format, 'Error in cgroup controller "{0}": {1}. {2}')
            self.assertEqual(controller, 'cpu')
            self.assertEqual(error, 'A test exception')
            self.assertEqual(message, 'A dummy message')


class MountCgroupsTestCase(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroups")
        self.mock_base_cgroups = patch("azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock_base_cgroups.start()

    def tearDown(self):
        self.mock_base_cgroups.stop()

    @staticmethod
    def _get_mount_commands(mock):
        mount_commands = ''
        for call_args in mock.call_args_list:
            args, kwargs = call_args # pylint: disable=unused-variable
            mount_commands += ';' + args[0]
        return mount_commands

    def test_mount_cgroups_should_mount_the_cpu_and_memory_controllers(self):
        # the mount command requires root privileges; make it a no op and check only for file existence
        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output) as patch_run_get_output:
            FileSystemCgroupsApi.mount_cgroups()

            # the directories for the controllers should have been created
            for controller in ['cpu', 'memory', 'cpuacct', 'cpu,cpuacct']:
                directory = os.path.join(self.cgroups_file_system_root, controller)
                self.assertTrue(os.path.exists(directory), "A directory for controller {0} was not created".format(controller))

            # the cgroup filesystem and the cpu and memory controllers should have been mounted
            mount_commands = MountCgroupsTestCase._get_mount_commands(patch_run_get_output)

            self.assertRegex(mount_commands, ';mount.* cgroup_root ', 'The cgroups file system was not mounted')
            self.assertRegex(mount_commands, ';mount.* cpu,cpuacct ', 'The cpu controller was not mounted')
            self.assertRegex(mount_commands, ';mount.* memory ', 'The memory controller was not mounted')

    def test_mount_cgroups_should_not_mount_the_cgroups_file_system_when_it_already_exists(self):
        os.mkdir(self.cgroups_file_system_root)

        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output) as patch_run_get_output:
            FileSystemCgroupsApi.mount_cgroups()

            mount_commands = MountCgroupsTestCase._get_mount_commands(patch_run_get_output)

            self.assertNotIn('cgroup_root', mount_commands, 'The cgroups file system should not have been mounted')
            self.assertRegex(mount_commands, ';mount.* cpu,cpuacct ', 'The cpu controller was not mounted')
            self.assertRegex(mount_commands, ';mount.* memory ', 'The memory controller was not mounted')

    def test_mount_cgroups_should_not_mount_cgroup_controllers_when_they_already_exist(self):
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, 'cpu,cpuacct'))
        os.mkdir(os.path.join(self.cgroups_file_system_root, 'memory'))

        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output) as patch_run_get_output:
            FileSystemCgroupsApi.mount_cgroups()

            mount_commands = MountCgroupsTestCase._get_mount_commands(patch_run_get_output)

            self.assertNotIn('cgroup_root', mount_commands, 'The cgroups file system should not have been mounted')
            self.assertNotIn('cpu,cpuacct', mount_commands, 'The cpu controller should not have been mounted')
            self.assertNotIn('memory', mount_commands, 'The memory controller should not have been mounted')

    def test_mount_cgroups_should_handle_errors_when_mounting_an_individual_controller(self):
        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                if 'memory' in cmd:
                    raise Exception('A test exception mounting the memory controller')
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output) as patch_run_get_output:
            with patch("azurelinuxagent.common.cgroupconfigurator.logger.warn") as mock_logger_warn:
                FileSystemCgroupsApi.mount_cgroups()

                # the cgroup filesystem and the cpu controller should still have been mounted
                mount_commands = MountCgroupsTestCase._get_mount_commands(patch_run_get_output)

                self.assertRegex(mount_commands, ';mount.* cgroup_root ', 'The cgroups file system was not mounted')
                self.assertRegex(mount_commands, ';mount.* cpu,cpuacct ', 'The cpu controller was not mounted')

                # A warning should have been logged for the memory controller
                args, kwargs = mock_logger_warn.call_args # pylint: disable=unused-variable
                self.assertIn('A test exception mounting the memory controller', args)

    def test_mount_cgroups_should_raise_when_the_cgroups_filesystem_fails_to_mount(self):
        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                if 'cgroup_root' in cmd:
                    raise Exception('A test exception mounting the cgroups file system')
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output) as patch_run_get_output:
            with self.assertRaises(Exception) as context_manager:
                FileSystemCgroupsApi.mount_cgroups()

            self.assertRegex(str(context_manager.exception), 'A test exception mounting the cgroups file system')

            mount_commands = MountCgroupsTestCase._get_mount_commands(patch_run_get_output)
            self.assertNotIn('memory', mount_commands, 'The memory controller should not have been mounted')
            self.assertNotIn('cpu', mount_commands, 'The cpu controller should not have been mounted')

    def test_mount_cgroups_should_raise_when_all_controllers_fail_to_mount(self):
        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                if 'memory' in cmd or 'cpu,cpuacct' in cmd:
                    raise Exception('A test exception mounting a cgroup controller')
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output):
            with self.assertRaises(Exception) as context_manager:
                FileSystemCgroupsApi.mount_cgroups()

            self.assertRegex(str(context_manager.exception), 'A test exception mounting a cgroup controller')

    def test_mount_cgroups_should_not_create_symbolic_links_when_the_cpu_controller_fails_to_mount(self):
        original_run_get_output = shellutil.run_get_output

        def mock_run_get_output(cmd, *args, **kwargs):
            if cmd.startswith('mount '):
                if 'cpu,cpuacct' in cmd:
                    raise Exception('A test exception mounting the cpu controller')
                return 0, None
            return original_run_get_output(cmd, *args, **kwargs)

        with patch("azurelinuxagent.common.osutil.default.shellutil.run_get_output", side_effect=mock_run_get_output):
            with patch("azurelinuxagent.common.osutil.default.os.symlink") as patch_symlink:
                FileSystemCgroupsApi.mount_cgroups()

                self.assertEqual(patch_symlink.call_count, 0, 'A symbolic link should not have been created')


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
        self.assertEqual(len(mock_add_event.call_args_list), 2)
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

            args, kwargs = mock_logger_warn.call_args # pylint: disable=unused-variable
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
    def test_start_extension_command_should_add_the_child_process_to_the_extension_cgroup(self, _): # pylint: disable=too-many-locals
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
        m = pattern.match(process_output) # pylint: disable=invalid-name

        try:
            pid_from_output = int(m.group(1))
        except Exception as e: # pylint: disable=invalid-name
            self.fail("No PID could be extracted from the process output! Error: {0}".format(ustr(e)))

        for cgroup in extension_cgroups:
            cgroups_procs_path = os.path.join(cgroup.path, "cgroup.procs")
            with open(cgroups_procs_path, "r") as f: # pylint: disable=invalid-name
                contents = f.read()
            pid_from_cgroup = int(contents)

            self.assertEqual(pid_from_output, pid_from_cgroup,
                              "The PID from the process output ({0}) does not match the PID found in the"
                              "process cgroup {1} ({2})".format(pid_from_output, cgroups_procs_path, pid_from_cgroup))


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
        root_slice_name = SystemdCgroupsApi()._get_extensions_slice_root_name() # pylint: disable=protected-access
        self.assertEqual(root_slice_name, "system-walinuxagent.extensions.slice")

    def test_get_extension_slice_name_should_return_the_slice_for_the_given_extension(self):
        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        extension_slice_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name) # pylint: disable=protected-access
        self.assertEqual(extension_slice_name, "system-walinuxagent.extensions-Microsoft.Azure.DummyExtension_1.0.slice")

    @attr('requires_sudo')
    def test_create_extension_cgroups_root_should_create_extensions_root_slice(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        SystemdCgroupsApi().create_extension_cgroups_root()

        unit_name = SystemdCgroupsApi()._get_extensions_slice_root_name() # pylint: disable=protected-access
        _, status = shellutil.run_get_output("systemctl status {0}".format(unit_name))
        self.assertIn("Loaded: loaded", status)
        self.assertIn("Active: active", status)

        shellutil.run_get_output("systemctl stop {0}".format(unit_name))
        shellutil.run_get_output("systemctl disable {0}".format(unit_name))
        os.remove("/etc/systemd/system/{0}".format(unit_name))
        shellutil.run_get_output("systemctl daemon-reload")

    def test_get_processes_in_cgroup_should_return_the_processes_within_the_cgroup(self):
        with mock_cgroup_commands():
            processes = SystemdCgroupsApi.get_processes_in_cgroup("/sys/fs/cgroup/cpu/system.slice/walinuxagent.service")

            self.assertTrue(len(processes) >= 2,
                            "The cgroup should contain at least 2 procceses (daemon and extension handler): [{0}]".format(processes))

            daemon_present = any("waagent -daemon" in command for (pid, command) in processes)
            self.assertTrue(daemon_present, "Could not find the daemon in the cgroup: [{0}]".format(processes))

            extension_handler_present = any(re.search(r"(WALinuxAgent-.+\.egg|waagent) -run-exthandlers", command) for (pid, command) in processes)
            self.assertTrue(extension_handler_present, "Could not find the extension handler in the cgroup: [{0}]".format(processes))

    @attr('requires_sudo')
    def test_create_extension_cgroups_should_create_extension_slice(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        cgroups = SystemdCgroupsApi().create_extension_cgroups(extension_name)
        cpu_cgroup, memory_cgroup = cgroups[0], cgroups[1]
        self.assertEqual(cpu_cgroup.path, "/sys/fs/cgroup/cpu/system.slice/Microsoft.Azure.DummyExtension_1.0")
        self.assertEqual(memory_cgroup.path, "/sys/fs/cgroup/memory/system.slice/Microsoft.Azure.DummyExtension_1.0")

        unit_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name) # pylint: disable=protected-access
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
    def test_start_extension_command_should_return_the_command_output(self, _):
        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            if command.startswith('systemd-run --unit=Microsoft.Compute.TestExtension_1.2.3'):
                command = "echo TEST_OUTPUT"
            return original_popen(command, *args, **kwargs)

        with mock_cgroup_commands() as mock_commands: # pylint: disable=unused-variable
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patch: # pylint: disable=unused-variable
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

            tracked = CGroupsTelemetry._tracked # pylint: disable=protected-access

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

                    self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created") # pylint: disable=protected-access

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

                    self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created") # pylint: disable=protected-access

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
    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args): # pylint: disable=unused-argument
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

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event: # pylint: disable=unused-variable
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
                legacy_cgroups = SystemdCgroupsApi().cleanup_legacy_cgroups()

        self.assertEqual(legacy_cgroups, 2, "cleanup_legacy_cgroups() did not find all the expected cgroups")
        self.assertFalse(os.path.exists(legacy_cpu_cgroup), "cleanup_legacy_cgroups() did not remove the CPU legacy cgroup")
        self.assertFalse(os.path.exists(legacy_memory_cgroup), "cleanup_legacy_cgroups() did not remove the memory legacy cgroup")
