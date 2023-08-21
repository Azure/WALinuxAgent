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

from azurelinuxagent.ga.cgroupapi import CGroupsApi, SystemdCgroupsApi
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import fileutil
from tests.lib.mock_cgroup_environment import mock_cgroup_environment
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


class CGroupsApiTestCase(_MockedFileSystemTestCase):
    def test_cgroups_should_be_supported_only_on_ubuntu16_centos7dot4_redhat7dot4_and_later_versions(self):
        test_cases = [
            (['ubuntu', '16.04', 'xenial'], True),
            (['ubuntu', '16.10', 'yakkety'], True),
            (['ubuntu', '18.04', 'bionic'], True),
            (['ubuntu', '18.10', 'cosmic'], True),
            (['ubuntu', '20.04', 'focal'], True),
            (['ubuntu', '20.10', 'groovy'], True),
            (['centos', '7.8', 'Source'], False),
            (['redhat', '7.8', 'Maipo'], False),
            (['redhat', '7.9.1908', 'Core'], False),
            (['centos', '8.1', 'Source'], False),
            (['redhat', '8.2', 'Maipo'], False),
            (['redhat', '8.2.2111', 'Core'], False),
            (['centos', '7.4', 'Source'], False),
            (['redhat', '7.4', 'Maipo'], False),
            (['centos', '7.5', 'Source'], False),
            (['centos', '7.3', 'Maipo'], False),
            (['redhat', '7.2', 'Maipo'], False),
            (['bigip', '15.0.1', 'Final'], False),
            (['gaia', '273.562', 'R80.30'], False),
            (['debian', '9.1', ''], False),
        ]

        for (distro, supported) in test_cases:
            with patch("azurelinuxagent.ga.cgroupapi.get_distro", return_value=distro):
                self.assertEqual(CGroupsApi.cgroups_supported(), supported, "cgroups_supported() failed on {0}".format(distro))

                
class SystemdCgroupsApiTestCase(AgentTestCase):
    def test_get_systemd_version_should_return_a_version_number(self):
        with mock_cgroup_environment(self.tmp_dir):
            version_info = systemd.get_version()
            found = re.search(r"systemd \d+", version_info) is not None
            self.assertTrue(found, "Could not determine the systemd version: {0}".format(version_info))

    def test_get_cpu_and_memory_mount_points_should_return_the_cgroup_mount_points(self):
        with mock_cgroup_environment(self.tmp_dir):
            cpu, memory = SystemdCgroupsApi().get_cgroup_mount_points()
            self.assertEqual(cpu, '/sys/fs/cgroup/cpu,cpuacct', "The mount point for the CPU controller is incorrect")
            self.assertEqual(memory, '/sys/fs/cgroup/memory', "The mount point for the memory controller is incorrect")

    def test_get_service_cgroup_paths_should_return_the_cgroup_mount_points(self):
        with mock_cgroup_environment(self.tmp_dir):
            cpu, memory = SystemdCgroupsApi().get_unit_cgroup_paths("extension.service")
            self.assertIn(cpu, '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service',
                          "The mount point for the CPU controller is incorrect")
            self.assertIn(memory, '/sys/fs/cgroup/memory/system.slice/extension.service',
                          "The mount point for the memory controller is incorrect")

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_relative_paths(self):
        with mock_cgroup_environment(self.tmp_dir):
            cpu, memory = SystemdCgroupsApi.get_process_cgroup_relative_paths('self')
            self.assertEqual(cpu, "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEqual(memory, "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")

    def test_get_cgroup2_controllers_should_return_the_v2_cgroup_controllers(self):
        with mock_cgroup_environment(self.tmp_dir):
            mount_point, controllers = SystemdCgroupsApi.get_cgroup2_controllers()

            self.assertEqual(mount_point, "/sys/fs/cgroup/unified", "Invalid mount point for V2 cgroups")
            self.assertIn("cpu", controllers, "The CPU controller is not in the list of V2 controllers")
            self.assertIn("memory", controllers, "The memory controller is not in the list of V2 controllers")

    def test_get_unit_property_should_return_the_value_of_the_given_property(self):
        with mock_cgroup_environment(self.tmp_dir):
            cpu_accounting = systemd.get_unit_property("walinuxagent.service", "CPUAccounting")

            self.assertEqual(cpu_accounting, "no", "Property {0} of {1} is incorrect".format("CPUAccounting", "walinuxagent.service"))

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
            if command.startswith('systemd-run --property'):
                command = "echo TEST_OUTPUT"
            return original_popen(command, *args, **kwargs)

        with mock_cgroup_environment(self.tmp_dir):
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("subprocess.Popen", side_effect=mock_popen) as popen_patch:  # pylint: disable=unused-variable
                    command_output = SystemdCgroupsApi().start_extension_command(
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
    def test_start_extension_command_should_execute_the_command_in_a_cgroup(self, _):
        with mock_cgroup_environment(self.tmp_dir):
            SystemdCgroupsApi().start_extension_command(
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
                any(cg for cg in tracked.values() if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
                "The extension's CPU is not being tracked")

            self.assertTrue(
                any(cg for cg in tracked.values() if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'memory' in cg.path),
                "The extension's Memory is not being tracked")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_use_systemd_to_execute_the_command(self, _):
        with mock_cgroup_environment(self.tmp_dir):
            with patch("subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                SystemdCgroupsApi().start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    cmd_name="test",
                    timeout=300,
                    shell=True,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if "the-test-extension-command" in args[0]]

                self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                self.assertIn("systemd-run", extension_calls[0], "The extension should have been invoked using systemd")


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
