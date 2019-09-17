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

import subprocess

from azurelinuxagent.common.cgroupapi import CGroupsApi, FileSystemCgroupsApi, SystemdCgroupsApi, VM_AGENT_CGROUP_NAME
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.processutil import read_output
from nose.plugins.attrib import attr
from tests.tools import *


class CGroupsApiTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

        self.mock__base_cgroups = patch("azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock__base_cgroups.start()

    def tearDown(self):
        self.mock__base_cgroups.stop()

    def test_create_should_return_a_SystemdCgroupsApi_on_systemd_platforms(self):
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=True):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == SystemdCgroupsApi)

    def test_create_should_return_a_FileSystemCgroupsApi_on_non_systemd_platforms(self):
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False):
            api = CGroupsApi.create()

        self.assertTrue(type(api) == FileSystemCgroupsApi)

    def test_is_systemd_should_return_true_when_systemd_manages_current_process(self):
        fileutil_read_file = fileutil.read_file

        def mock_read_file(filepath, asbin=False, remove_bom=False, encoding='utf-8'):
            if filepath == "/proc/cgroups":
                return """
#subsys_name	hierarchy	num_cgroups	enabled
cpuset	11	1	1
cpu	3	77	1
cpuacct	3	77	1
blkio	10	70	1
memory	12	124	1
devices	9	70	1
freezer	4	1	1
net_cls	2	1	1
perf_event	7	1	1
net_prio	2	1	1
hugetlb	8	1	1
pids	5	76	1
rdma	6	1	1
"""
            if filepath == "/proc/self/cgroup":
                return """
12:memory:/system.slice/walinuxagent.service
11:cpuset:/
10:blkio:/system.slice/walinuxagent.service
9:devices:/system.slice/walinuxagent.service
8:hugetlb:/
7:perf_event:/
6:rdma:/
5:pids:/system.slice/walinuxagent.service
4:freezer:/
3:cpu,cpuacct:/system.slice/walinuxagent.service
2:net_cls,net_prio:/
1:name=systemd:/system.slice/walinuxagent.service
0::/system.slice/walinuxagent.service
"""
            return fileutil_read_file(filepath, asbin=asbin, remove_bom=remove_bom, encoding=encoding)

        with patch("azurelinuxagent.common.cgroupapi.fileutil.read_file", mock_read_file):
            is_systemd = CGroupsApi._is_systemd()

        self.assertTrue(is_systemd)

    def test_is_systemd_should_return_false_when_systemd_does_not_manage_current_process(self):
        fileutil_read_file = fileutil.read_file

        def mock_read_file(filepath, asbin=False, remove_bom=False, encoding='utf-8'):
            if filepath == "/proc/cgroups":
                return """
#subsys_name	hierarchy	num_cgroups	enabled
cpuset	11	1	1
cpu	3	77	1
cpuacct	3	77	1
blkio	10	70	1
memory	12	124	1
devices	9	70	1
freezer	4	1	1
net_cls	2	1	1
perf_event	7	1	1
net_prio	2	1	1
hugetlb	8	1	1
pids	5	76	1
rdma	6	1	1
"""
            if filepath == "/proc/self/cgroup":
                return """
3:name=systemd:/
2:memory:/walinuxagent.service
1:cpu,cpuacct:/walinuxagent.service
"""
            return fileutil_read_file(filepath, asbin=asbin, remove_bom=remove_bom, encoding=encoding)

        with patch("azurelinuxagent.common.cgroupapi.fileutil.read_file", mock_read_file):
            is_systemd = CGroupsApi._is_systemd()

        self.assertFalse(is_systemd)

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
            message = args[0]
            self.assertIn('Error in cgroup controller "cpu": A test exception.', message)


class FileSystemCgroupsApiTestCase(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

        self.mock__base_cgroups = patch("azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock__base_cgroups.start()

    def tearDown(self):
        self.mock__base_cgroups.stop()

        AgentTestCase.tearDown(self)

    def test_cleanup_old_cgroups_should_move_daemon_pid_on_all_controllers(self):
        # Set up the mock /var/run/waagent.pid file
        daemon_pid = "42"
        daemon_pid_file_tmp = os.path.join(self.tmp_dir, "waagent.pid")
        with open(daemon_pid_file_tmp, "w") as f:
            f.write(daemon_pid)

        # Set up old controller cgroups and add the daemon PID to them
        old_cpu_cgroup = os.path.join(self.cgroups_file_system_root, "cpu", "WALinuxAgent", "WALinuxAgent")
        old_memory_cgroup = os.path.join(self.cgroups_file_system_root, "memory", "WALinuxAgent", "WALinuxAgent")

        os.makedirs(old_cpu_cgroup)
        os.makedirs(old_memory_cgroup)

        fileutil.write_file(os.path.join(old_cpu_cgroup, "cgroup.procs"), daemon_pid + "\n")
        fileutil.write_file(os.path.join(old_memory_cgroup, "cgroup.procs"), daemon_pid + "\n")

        # Set up new controller cgroups and add another PID to them
        new_cpu_cgroup = os.path.join(self.cgroups_file_system_root, "cpu", VM_AGENT_CGROUP_NAME)
        new_memory_cgroup = os.path.join(self.cgroups_file_system_root, "memory", VM_AGENT_CGROUP_NAME)

        os.makedirs(new_cpu_cgroup)
        os.makedirs(new_memory_cgroup)

        fileutil.write_file(os.path.join(new_cpu_cgroup, "cgroup.procs"), "999\n")
        fileutil.write_file(os.path.join(new_memory_cgroup, "cgroup.procs"), "999\n")

        with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
            with patch("azurelinuxagent.common.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file_tmp):
                FileSystemCgroupsApi().cleanup_old_cgroups()

        # The method should have added the daemon PID to the new controllers and deleted the old ones
        new_cpu_contents = fileutil.read_file(os.path.join(new_cpu_cgroup, "cgroup.procs"))
        new_memory_contents = fileutil.read_file(os.path.join(new_memory_cgroup, "cgroup.procs"))

        self.assertTrue(daemon_pid in new_cpu_contents)
        self.assertTrue(daemon_pid in new_memory_contents)

        self.assertFalse(os.path.exists(old_cpu_cgroup))
        self.assertFalse(os.path.exists(old_memory_cgroup))

        # Assert the event parameters that were sent out
        _, kwargs = mock_add_event.call_args_list[0]
        self.assertEquals(kwargs['op'], 'CGroupsCleanUp')
        self.assertEquals(kwargs['is_success'], True)
        self.assertEquals(kwargs['message'], 'Successfully cleaned up old cgroups in WALinuxAgent/WALinuxAgent.')

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

    def test_start_extension_command_should_add_the_child_process_to_the_extension_cgroup(self):
        api = FileSystemCgroupsApi()
        api.create_extension_cgroups_root()

        process, extension_cgroups = api.start_extension_command(
            extension_name="Microsoft.Compute.TestExtension-1.2.3",
            command="date",
            shell=False,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        process.wait()

        for cgroup in extension_cgroups:
            cgroups_procs_path = os.path.join(cgroup.path, "cgroup.procs")
            with open(cgroups_procs_path, "r") as f:
                contents = f.read()
            pid = int(contents)

            self.assertEquals(pid, process.pid, "The PID of the command was not added to {0}. Expected: {1}, got: {2}".format(cgroups_procs_path, process.pid, pid))


@skip_if_predicate_false(is_systemd_present, "Systemd cgroups API doesn't manage cgroups on systems not using systemd.")
class SystemdCgroupsApiTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_it_should_return_extensions_slice_root_name(self):
        root_slice_name = SystemdCgroupsApi()._get_extensions_slice_root_name()
        self.assertEqual(root_slice_name, "system-walinuxagent.extensions.slice")

    def test_it_should_return_extension_slice_name(self):
        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        extension_slice_name = SystemdCgroupsApi()._get_extension_slice_name(extension_name)
        self.assertEqual(extension_slice_name, "system-walinuxagent.extensions-Microsoft.Azure.DummyExtension_1.0.slice")

    @attr('requires_sudo')
    def test_it_should_create_extensions_root_slice(self):
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
    def test_it_should_create_extension_slice(self):
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

    def test_start_extension_command_should_create_extension_scopes(self):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            return original_popen("date", **kwargs)

        # we mock subprocess.Popen to execute a dummy command (date), so no actual cgroups are created; their paths
        # should be computed properly, though
        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", mock_popen):
            process, extension_cgroups = SystemdCgroupsApi().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="date",
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            process.wait()
            self.assert_cgroups_created(extension_cgroups)

    @attr('requires_sudo')
    def test_start_extension_command_should_use_systemd_if_not_failing(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            return original_popen(*args, **kwargs)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patch_mock_popen:
                    process, extension_cgroups = SystemdCgroupsApi().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="date",
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    process.wait()

                    ret = process.poll()

                    # We should have invoked the extension command only once and succeeded
                    self.assertEquals(0, ret)
                    self.assertEquals(1, patch_mock_popen.call_count)

                    args = patch_mock_popen.call_args[0][0]
                    self.assertIn("systemd-run --unit", args)

                    self.assert_cgroups_created(extension_cgroups)

    def test_start_extension_command_should_not_use_systemd_if_failing(self):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Inject a syntax error to the call
            systemd_command = args[0].replace('systemd-run', 'systemd-run syntax_error')
            new_args = (systemd_command,)
            return original_popen(new_args, **kwargs)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patch_mock_popen:

                        # We expect this call to fail because of the syntax error
                        process, extension_cgroups = SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="date",
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        process.wait()

                        args, kwargs = mock_add_event.call_args
                        self.assertIn("Failed to run systemd-run for unit Microsoft.Compute.TestExtension_1.2.3",
                                      kwargs['message'])
                        self.assertIn("Failed to find executable syntax_error: No such file or directory",
                                      kwargs['message'])
                        self.assertEquals(False, kwargs['is_success'])
                        self.assertEquals('InvokeCommandUsingSystemd', kwargs['op'])

                        # We expect the process to ultimately succeed since the fallback option worked
                        ret = process.poll()
                        self.assertEquals(0, ret)

                        # We expect two calls to Popen, first for the systemd-run call, second for the fallback option
                        self.assertEquals(2, patch_mock_popen.call_count)

                        first_call_args = patch_mock_popen.mock_calls[0][1][0]
                        second_call_args = patch_mock_popen.mock_calls[1][1][0]
                        self.assertIn("systemd-run --unit", first_call_args)
                        self.assertNotIn("systemd-run --unit", second_call_args)

                        # No cgroups should have been created
                        self.assertEquals(extension_cgroups, [])

    def test_start_extension_command_should_capture_only_the_last_subprocess_output(self):
        original_popen = subprocess.Popen

        def mock_popen(*args, **kwargs):
            # Inject a syntax error to the call
            systemd_command = args[0].replace('systemd-run', 'systemd-run syntax_error')
            new_args = (systemd_command,)
            return original_popen(new_args, **kwargs)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.common.cgroupapi.add_event") as mock_add_event:
                    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen",
                               side_effect=mock_popen) as patch_mock_popen:
                        # We expect this call to fail because of the syntax error
                        process, extension_cgroups = SystemdCgroupsApi().start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="echo 'very specific test message'",
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        process.wait()
                        process_output = read_output(stdout, stderr)
                        self.assertEquals("[stdout]\nvery specific test message\n\n\n[stderr]\n", process_output)

    @patch("azurelinuxagent.common.utils.fileutil.read_file")
    def test_create_agent_cgroups_should_create_cgroups_on_all_controllers(self, patch_read_file):
        mock__base_cgroups = patch("azurelinuxagent.common.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT",
                                   self.cgroups_file_system_root)
        mock__base_cgroups.start()
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
            expected_cgroup_path = os.path.join(self.cgroups_file_system_root, controller, "system.slice", VM_AGENT_CGROUP_NAME)

            self.assertTrue(any(cgroups.path == expected_cgroup_path for cgroups in agent_cgroups))
            self.assertTrue(any(cgroups.name == VM_AGENT_CGROUP_NAME for cgroups in agent_cgroups))

        assert_cgroup_created("cpu")
        assert_cgroup_created("memory")
        mock__base_cgroups.stop()
