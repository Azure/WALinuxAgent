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

from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.utils.fileutil import read_file
from azurelinuxagent.ga import cgroupapi
from azurelinuxagent.ga.cgroupapi import CGroupsApi, SystemdCgroupsApi, SystemdCgroupsApiv1, SystemdCgroupsApiv2
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import fileutil
from tests.lib.mock_cgroup_environment import mock_cgroup_v1_environment, mock_cgroup_v2_environment, \
    mock_cgroup_v1_and_v2_environment
from tests.lib.tools import AgentTestCase, patch, mock_sleep
from tests.lib.cgroups_tools import CGroupsTools

class _MockedFileSystemTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

        self.mock_cgroups_file_system_root = patch("azurelinuxagent.ga.cgroupapi.CGROUPS_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock_cgroups_file_system_root.start()

    def tearDown(self):
        self.mock_cgroups_file_system_root.stop()
        AgentTestCase.tearDown(self)


class CGroupsApiTestCase(AgentTestCase):
    def test_get_cgroup_api_is_v1_when_v1_controllers_mounted(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            self.assertIsInstance(cgroupapi.get_cgroup_api(), SystemdCgroupsApiv1)

    def test_get_cgroup_api_is_v2_when_v2_controllers_mounted(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertIsInstance(cgroupapi.get_cgroup_api(), SystemdCgroupsApiv2)

    def test_get_cgroup_api_is_v1_when_v1_and_v2_controllers_mounted(self):
        with mock_cgroup_v1_and_v2_environment(self.tmp_dir):
            self.assertIsInstance(cgroupapi.get_cgroup_api(), SystemdCgroupsApiv1)

    def test_get_cgroup_api_is_none_when_no_controllers_mounted(self):
        with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_cgroup_mount_points", return_value=(None,None)):
            with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_cgroup_mount_points", return_value=(None,None)):
                self.assertIsNone(cgroupapi.get_cgroup_api())

    def test_cgroups_should_be_supported_only_on_ubuntu16_centos7dot4_redhat7dot4_and_later_versions(self):
        test_cases = [
            (['ubuntu', '16.04', 'xenial'], True),
            (['ubuntu', '16.10', 'yakkety'], True),
            (['ubuntu', '18.04', 'bionic'], True),
            (['ubuntu', '18.10', 'cosmic'], True),
            (['ubuntu', '20.04', 'focal'], True),
            (['ubuntu', '20.10', 'groovy'], True),
            (['centos', '7.4', 'Source'], False),
            (['redhat', '7.4', 'Maipo'], False),
            (['centos', '7.5', 'Source'], False),
            (['centos', '7.3', 'Maipo'], False),
            (['redhat', '7.2', 'Maipo'], False),
            (['centos', '7.8', 'Source'], False),
            (['redhat', '7.8', 'Maipo'], False),
            (['redhat', '7.9.1908', 'Core'], False),
            (['centos', '8.1', 'Source'], True),
            (['redhat', '8.2', 'Maipo'], True),
            (['redhat', '8.2.2111', 'Core'], True),
            (['redhat', '9.1', 'Core'], False),
            (['centos', '9.1', 'Source'], False),
            (['bigip', '15.0.1', 'Final'], False),
            (['gaia', '273.562', 'R80.30'], False),
            (['debian', '9.1', ''], False),
        ]

        for (distro, supported) in test_cases:
            with patch("azurelinuxagent.ga.cgroupapi.get_distro", return_value=distro):
                self.assertEqual(CGroupsApi.cgroups_supported(), supported, "cgroups_supported() failed on {0}".format(distro))

                
class SystemdCgroupsApiTestCase(AgentTestCase):
    def test_get_systemd_version_should_return_a_version_number(self):
        # We expect same behavior for v1 and v2
        mock_envs = [mock_cgroup_v1_environment(self.tmp_dir), mock_cgroup_v2_environment(self.tmp_dir)]
        for env in mock_envs:
            with env:
                version_info = systemd.get_version()
                found = re.search(r"systemd \d+", version_info) is not None
                self.assertTrue(found, "Could not determine the systemd version: {0}".format(version_info))

    def test_is_cpu_or_memory_mounted_true_if_only_memory_mounted(self):
        with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi.get_cgroup_mount_points", return_value=(None, '/sys/fs/cgroup/memory')):
            self.assertTrue(SystemdCgroupsApi().is_cpu_or_memory_mounted())

    def test_is_cpu_or_memory_mounted_true_if_only_cpu_mounted(self):
        with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi.get_cgroup_mount_points", return_value=('/sys/fs/cgroup/cpu,cpuacct', None)):
            self.assertTrue(SystemdCgroupsApi().is_cpu_or_memory_mounted())

    def test_is_cpu_or_memory_mounted_true_if_cpu_and_memory_mounted(self):
        with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi.get_cgroup_mount_points", return_value=('/sys/fs/cgroup/cpu,cpuacct', '/sys/fs/cgroup/memory')):
            self.assertTrue(SystemdCgroupsApi().is_cpu_or_memory_mounted())

    def test_is_cpu_or_memory_mounted_false_if_cpu_and_memory_not_mounted(self):
        with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi.get_cgroup_mount_points", return_value=(None, None)):
            self.assertFalse(SystemdCgroupsApi().is_cpu_or_memory_mounted())

    def test_get_mounted_controllers_has_cpu_and_memory_controllers(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            mounted_controllers = cgroupapi.get_cgroup_api().get_mounted_controllers()
            self.assertTrue("cpu" in mounted_controllers)
            self.assertTrue("memory" in mounted_controllers)

        with mock_cgroup_v2_environment(self.tmp_dir):
            mounted_controllers = cgroupapi.get_cgroup_api().get_mounted_controllers()
            self.assertTrue("cpu" in mounted_controllers)
            self.assertTrue("memory" in mounted_controllers)

        with mock_cgroup_v1_and_v2_environment(self.tmp_dir):
            mounted_controllers = cgroupapi.get_cgroup_api().get_mounted_controllers()  # API will be v1 since this environment as CPU mounted in v1
            self.assertTrue("cpu" in mounted_controllers)
            self.assertFalse("memory" in mounted_controllers) # This environment has memory mounted in v2

    def test_get_unit_property_should_return_the_value_of_the_given_property(self):
        # We expect same behavior for v1 and v2
        mock_envs = [mock_cgroup_v1_environment(self.tmp_dir), mock_cgroup_v2_environment(self.tmp_dir)]
        for env in mock_envs:
            with env:
                cpu_accounting = systemd.get_unit_property("walinuxagent.service", "CPUAccounting")

                self.assertEqual(cpu_accounting, "no", "Property {0} of {1} is incorrect".format("CPUAccounting", "walinuxagent.service"))


class SystemdCgroupsApiv1TestCase(AgentTestCase):
    def test_get_unit_cgroup_paths_should_return_the_cgroup_v1_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
            self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service',
                          "The mount point for the CPU controller is incorrect")
            self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/extension.service',
                          "The mount point for the memory controller is incorrect")

    def test_get_unit_cgroup_path_should_return_None_if_either_cgroup_v1_controller_not_mounted(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_cgroup_mount_points', return_value=('/sys/fs/cgroup/cpu,cpuacct', None)):
                cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(memory,
                                  "The mount point for the memory controller is None so unit cgroup should be None")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_cgroup_mount_points', return_value=(None, '/sys/fs/cgroup/memory')):
                cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIsNone(cpu, "The mount point for the cpu controller is None so unit cgroup should be None")
                self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/extension.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_paths_should_return_the_cgroup_v1_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
            self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                          "The mount point for the CPU controller is incorrect")
            self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                          "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_path_should_return_None_if_either_cgroup_v1_controller_not_mounted(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_cgroup_mount_points', return_value=('/sys/fs/cgroup/cpu,cpuacct', None)):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(memory,
                                  "The mount point for the memory controller is None so unit cgroup should be None")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_cgroup_mount_points', return_value=(None, '/sys/fs/cgroup/memory')):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(cpu, "The mount point for the CPU controller is None so unit cgroup should be None")
                self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_v1_path_should_return_None_if_either_relative_path_is_None(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_process_cgroup_relative_paths', return_value=('system.slice/walinuxagent.service', None)):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(memory,
                                  "The relative cgroup path for the memory controller is None so unit cgroup should be None")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv1.get_process_cgroup_relative_paths', return_value=(None, 'system.slice/walinuxagent.service')):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(cpu, "The relative cgroup path for the cpu controller is None so unit cgroup should be None")
                self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_mount_points_should_return_the_cgroup_v1_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_cgroup_mount_points()
            self.assertEqual(cpu, '/sys/fs/cgroup/cpu,cpuacct', "The mount point for the CPU controller is incorrect")
            self.assertEqual(memory, '/sys/fs/cgroup/memory', "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_v1_relative_paths(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_relative_paths('self')
            self.assertEqual(cpu, "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEqual(memory, "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_return_the_command_output(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            original_popen = subprocess.Popen

            def mock_popen(command, *args, **kwargs):
                if isinstance(command, str) and command.startswith('systemd-run --property'):
                    command = "echo TEST_OUTPUT"
                return original_popen(command, *args, **kwargs)

            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("subprocess.Popen",
                           side_effect=mock_popen) as popen_patch:  # pylint: disable=unused-variable
                    command_output = cgroupapi.get_cgroup_api().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="A_TEST_COMMAND",
                        cmd_name="test",
                        shell=True,
                        timeout=300,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=output_file,
                        stderr=output_file)

                    self.assertIn("[stdout]\nTEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_execute_the_command_in_a_cgroup(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cgroupapi.get_cgroup_api().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                cmd_name="test",
                shell=False,
                timeout=300,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            tracked = CGroupsTelemetry._tracked

            self.assertTrue(
                any(cg for cg in tracked.values() if
                    cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
                "The extension's CPU is not being tracked")

            self.assertTrue(
                any(cg for cg in tracked.values() if
                    cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'memory' in cg.path),
                "The extension's Memory is not being tracked")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_use_systemd_to_execute_the_command(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch("subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                cgroupapi.get_cgroup_api().start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    cmd_name="test",
                    timeout=300,
                    shell=True,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if
                                   "the-test-extension-command" in args[0]]

                self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                self.assertIn("systemd-run", extension_calls[0], "The extension should have been invoked using systemd")


class SystemdCgroupsApiv2TestCase(AgentTestCase):
    def test_is_controller_enabled_should_return_False_if_cgroup_is_None(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertFalse(cgroupapi.get_cgroup_api().is_controller_enabled('cpu', None))

    def test_is_controller_enabled_should_return_False_if_controller_is_None(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertFalse(cgroupapi.get_cgroup_api().is_controller_enabled(None, '/sys/fs/cgroup'))

    def test_is_controller_enabled_should_return_False_if_cgroup_path_does_not_exist(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertFalse(cgroupapi.get_cgroup_api().is_controller_enabled('cpu', '/path/that/does/not/exist'))

    def test_is_controller_enabled_should_return_False_if_controller_is_not_in_subtree_control_file_and_controller_interface_files_do_not_exist(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertFalse(cgroupapi.get_cgroup_api().is_controller_enabled('cpu', '/sys/fs/cgroup/azure.slice/walinuxagent.service'))

    def test_is_controller_enabled_should_return_True_if_controller_is_in_subtree_control_file(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            # Mock the cgroup.subtree_control to include memory controller
            def mock_read_file(path):
                if "/sys/fs/cgroup/azure.slice/walinuxagent.service/cgroup.subtree_control" in path:
                    return 'io memory pids\n'
                return read_file(path)

            with patch('azurelinuxagent.common.utils.fileutil.read_file', side_effect=mock_read_file):
                self.assertTrue(cgroupapi.get_cgroup_api().is_controller_enabled('memory', '/sys/fs/cgroup/azure.slice/walinuxagent.service'))

    def test_is_controller_enabled_should_return_True_if_controller_interface_file_exists(self):
        original_list_dir = os.listdir

        # Mock the walinuxagent.service directory to include memory controller interface files
        def mock_os_list_dir(path):
            if "/sys/fs/cgroup/azure.slice/walinuxagent.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'memory.stat']
            return original_list_dir(path)

        with mock_cgroup_v2_environment(self.tmp_dir) as mock_env:
            # Mock service directory
            mock_env._mock_mkdir('/sys/fs/cgroup/azure.slice/walinuxagent.service')

            with patch('os.listdir', side_effect=mock_os_list_dir):
                self.assertTrue(cgroupapi.get_cgroup_api().is_controller_enabled('memory', '/sys/fs/cgroup/azure.slice/walinuxagent.service'))

    def test_get_unit_cgroup_paths_should_return_the_cgroup_v2_mount_points(self):
        original_list_dir = os.listdir

        # Mock the extension.service directory to include controller interface files
        def mock_os_list_dir(path):
            if "/sys/fs/cgroup/system.slice/extension.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'memory.stat', 'cpu.stat']
            return original_list_dir(path)

        with mock_cgroup_v2_environment(self.tmp_dir) as mock_env:
            # Mock service directory
            mock_env._mock_mkdir('/sys/fs/cgroup/system.slice/extension.service')

            with patch('os.listdir', side_effect=mock_os_list_dir):
                cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertEqual(cpu, '/sys/fs/cgroup/system.slice/extension.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertEqual(memory, '/sys/fs/cgroup/system.slice/extension.service',
                            "The mount point for the memory controller is incorrect")

    def test_get_unit_cgroup_path_should_return_None_if_either_cgroup_v2_controller_not_mounted(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.is_controller_enabled', return_value=True):
                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_cgroup_mount_points', return_value=('/sys/fs/cgroup', None)):
                    cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                    self.assertIn(cpu, '/sys/fs/cgroup/system.slice/extension.service',
                                  "The mount point for the CPU controller is incorrect")
                    self.assertIsNone(memory,
                                      "The mount point for the memory controller is None so unit cgroup should be None")

                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_cgroup_mount_points', return_value=(None, '/sys/fs/cgroup')):
                    cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                    self.assertIsNone(cpu, "The mount point for the cpu controller is None so unit cgroup should be None")
                    self.assertIn(memory, '/sys/fs/cgroup/system.slice/extension.service',
                                  "The mount point for the memory controller is incorrect")

    def test_get_unit_cgroup_path_should_return_None_if_either_cgroup_v2_controller_not_enabled(self):
        original_list_dir = os.listdir

        # Mock the extension.service directory to include only cpu controller interface files
        def mock_os_list_dir_cpu(path):
            if "/sys/fs/cgroup/system.slice/extension.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'cpu.stat']
            return original_list_dir(path)

        # Mock the extension.service directory to include only cpu controller interface files
        def mock_os_list_dir_memory(path):
            if "/sys/fs/cgroup/system.slice/extension.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'memory.stat']
            return original_list_dir(path)

        with mock_cgroup_v2_environment(self.tmp_dir) as mock_env:
            # Mock service directory
            mock_env._mock_mkdir('/sys/fs/cgroup/system.slice/extension.service')

            with patch('os.listdir', side_effect=mock_os_list_dir_cpu):
                cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIn(cpu, '/sys/fs/cgroup/system.slice/extension.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(memory,
                                  "The memory controller is not enabled so unit cgroup should be None")

            with patch('os.listdir', side_effect=mock_os_list_dir_memory):
                cpu, memory = cgroupapi.get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIsNone(cpu, "The cpu controller is not enabled so unit cgroup should be None")
                self.assertIn(memory, '/sys/fs/cgroup/system.slice/extension.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_paths_should_return_the_cgroup_v2_mount_points(self):
        original_list_dir = os.listdir

        # Mock the extension.service directory to include controller interface files
        def mock_os_list_dir(path):
            if "/sys/fs/cgroup/system.slice/walinuxagent.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'memory.stat', 'cpu.stat']
            return original_list_dir(path)

        with mock_cgroup_v2_environment(self.tmp_dir) as mock_env:
            # Mock service directory
            mock_env._mock_mkdir('/sys/fs/cgroup/system.slice/walinuxagent.service')

            with patch('os.listdir', side_effect=mock_os_list_dir):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIn(cpu, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIn(memory, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_path_should_return_None_if_either_cgroup_v2_controller_not_mounted(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.is_controller_enabled', return_value=True):
                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_cgroup_mount_points', return_value=('/sys/fs/cgroup', None)):
                    cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                    self.assertIn(cpu, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                                  "The mount point for the CPU controller is incorrect")
                    self.assertIsNone(memory,
                                      "The mount point for the memory controller is None so unit cgroup should be None")

                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_cgroup_mount_points', return_value=(None, '/sys/fs/cgroup')):
                    cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                    self.assertIsNone(cpu, "The mount point for the CPU controller is None so unit cgroup should be None")
                    self.assertIn(memory, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                                  "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_v2_path_should_return_None_if_either_relative_path_is_None(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.is_controller_enabled', return_value=True):
                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_process_cgroup_relative_paths', return_value=('system.slice/walinuxagent.service', None)):
                    cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                    self.assertIn(cpu, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                                  "The mount point for the CPU controller is incorrect")
                    self.assertIsNone(memory,
                                      "The relative cgroup path for the memory controller is None so unit cgroup should be None")

                with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupsApiv2.get_process_cgroup_relative_paths', return_value=(None, 'system.slice/walinuxagent.service')):
                    cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                    self.assertIsNone(cpu, "The relative cgroup path for the cpu controller is None so unit cgroup should be None")
                    self.assertIn(memory, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                                  "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_path_should_return_None_if_either_cgroup_v2_controller_not_enabled(self):
        original_list_dir = os.listdir

        # Mock the walinuxagent.service directory to include memory controller interface files
        def mock_os_list_dir_memory(path):
            if "/sys/fs/cgroup/system.slice/walinuxagent.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'memory.stat']
            return original_list_dir(path)

        # Mock the walinuxagent.service directory to include cpu controller interface files
        def mock_os_list_dir_cpu(path):
            if "/sys/fs/cgroup/system.slice/walinuxagent.service" in path:
                return ['cgroup.controllers', 'cgroup.subtree_control', 'cpu.stat']
            return original_list_dir(path)

        with mock_cgroup_v2_environment(self.tmp_dir) as mock_env:
            # Mock service directory
            mock_env._mock_mkdir('/sys/fs/cgroup/system.slice/walinuxagent.service')

            with patch('os.listdir', side_effect=mock_os_list_dir_cpu):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIn(cpu, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(memory,
                                  "The memory controller is not enabled so unit cgroup should be None")

            with patch('os.listdir', side_effect=mock_os_list_dir_memory):
                cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(cpu, "The cpu controller is not enabled so unit cgroup should be None")
                self.assertIn(memory, '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_mount_points_should_return_the_cgroup_v2_mount_points(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_cgroup_mount_points()
            self.assertEqual(cpu, '/sys/fs/cgroup', "The mount point for the CPU controller is incorrect")
            self.assertEqual(memory, '/sys/fs/cgroup', "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_v2_relative_paths(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            cpu, memory = cgroupapi.get_cgroup_api().get_process_cgroup_relative_paths('self')
            self.assertEqual(cpu, "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEqual(memory, "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v2_command_should_raise_exception(self, _):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                cgroups_exception_raised = False
                try:
                    cgroupapi.get_cgroup_api().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="A_TEST_COMMAND",
                        cmd_name="test",
                        shell=True,
                        timeout=300,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=output_file,
                        stderr=output_file)
                except CGroupsException:
                    cgroups_exception_raised = True
                self.assertTrue(cgroups_exception_raised)


class SystemdCgroupsApiMockedFileSystemTestCase(_MockedFileSystemTestCase):
    def test_cleanup_legacy_cgroups_should_remove_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, "42\n")

        # Set up old controller cgroups, but do not add the daemon's PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", '')
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", '')

        with patch("azurelinuxagent.ga.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
            legacy_cgroups = SystemdCgroupsApi().cleanup_legacy_cgroups()

        self.assertEqual(legacy_cgroups, 2, "cleanup_legacy_cgroups() did not find all the expected cgroups")
        self.assertFalse(os.path.exists(legacy_cpu_cgroup), "cleanup_legacy_cgroups() did not remove the CPU legacy cgroup")
        self.assertFalse(os.path.exists(legacy_memory_cgroup), "cleanup_legacy_cgroups() did not remove the memory legacy cgroup")
