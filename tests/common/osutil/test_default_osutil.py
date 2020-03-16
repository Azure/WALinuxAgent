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

from azurelinuxagent.common.osutil.default import DefaultOSUtil, shellutil
from tests.tools import AgentTestCase, patch
import os


class DefaultOsUtilTestCase(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroups")
        self.mock_base_cgroups = patch("azurelinuxagent.common.osutil.default.BASE_CGROUPS", self.cgroups_file_system_root)
        self.mock_base_cgroups.start()

    def tearDown(self):
        self.mock_base_cgroups.stop()

    @staticmethod
    def _get_mount_commands(mock):
        mount_commands = ''
        for call_args in mock.call_args_list:
            args, kwargs = call_args
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
            DefaultOSUtil().mount_cgroups()

            # the directories for the controllers should have been created
            for controller in ['cpu', 'memory', 'cpuacct', 'cpu,cpuacct']:
                directory = os.path.join(self.cgroups_file_system_root, controller)
                self.assertTrue(os.path.exists(directory), "A directory for controller {0} was not created".format(controller))

            # the cgroup filesystem and the cpu and memory controllers should have been mounted
            mount_commands = DefaultOsUtilTestCase._get_mount_commands(patch_run_get_output)

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
            DefaultOSUtil().mount_cgroups()

            mount_commands = DefaultOsUtilTestCase._get_mount_commands(patch_run_get_output)

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
            DefaultOSUtil().mount_cgroups()

            mount_commands = DefaultOsUtilTestCase._get_mount_commands(patch_run_get_output)

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
                DefaultOSUtil().mount_cgroups()

                # the cgroup filesystem and the cpu controller should still have been mounted
                mount_commands = DefaultOsUtilTestCase._get_mount_commands(patch_run_get_output)

                self.assertRegex(mount_commands, ';mount.* cgroup_root ', 'The cgroups file system was not mounted')
                self.assertRegex(mount_commands, ';mount.* cpu,cpuacct ', 'The cpu controller was not mounted')

                # A warning should have been logged for the memory controller
                args, kwargs = mock_logger_warn.call_args
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
                DefaultOSUtil().mount_cgroups()

            self.assertRegex(str(context_manager.exception), 'A test exception mounting the cgroups file system')

            mount_commands = DefaultOsUtilTestCase._get_mount_commands(patch_run_get_output)
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
                DefaultOSUtil().mount_cgroups()

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
                DefaultOSUtil().mount_cgroups()

                self.assertEquals(patch_symlink.call_count, 0, 'A symbolic link should not have been created')

    def test_default_service_name(self):
        self.assertEquals(DefaultOSUtil().get_service_name(), "waagent")
