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

from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from tests.tools import *


class CGroupConfiguratorTestCase(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        # Use the file system implementation of CGroupsApi (FileSystemCgroupsApi)
        cls.mock_is_systemd = patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False)
        cls.mock_is_systemd.start()

        # Use the default implementation of osutil
        cls.mock_get_osutil = patch("azurelinuxagent.common.cgroupconfigurator.get_osutil", return_value=DefaultOSUtil())
        cls.mock_get_osutil.start()

        # Currently osutil.is_cgroups_supported() returns False on Travis runs. We need to revisit this design; in the
        # meanwhile mock the method to return True
        cls.mock_is_cgroups_supported = patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.is_cgroups_supported", return_value=True)
        cls.mock_is_cgroups_supported.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_is_cgroups_supported.stop()
        cls.mock_get_osutil.stop()
        cls.mock_is_systemd.stop()

        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)
        CGroupConfigurator._instance = None  # force get_instance() to create a new instance for each test

    def test_init_should_mount_the_cgroups_file_system(self):
        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.mount_cgroups") as mock_mount_cgroups:
            CGroupConfigurator.get_instance()

        self.assertEqual(mock_mount_cgroups.call_count, 1)

    def test_init_should_disable_cgroups_when_they_are_not_supported(self):
        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.is_cgroups_supported", return_value=False):
            self.assertFalse(CGroupConfigurator.get_instance().enabled())

    def test_enable_and_disable_should_change_the_enabled_state_of_cgroups(self):
        configurator = CGroupConfigurator.get_instance()

        self.assertTrue(configurator.enabled())

        configurator.disable()
        self.assertFalse(configurator.enabled())

        configurator.enable()
        self.assertTrue(configurator.enabled())

    def test_enable_should_raise_CGroupsException_when_cgroups_are_not_supported(self):
        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.is_cgroups_supported", return_value=False):
            with self.assertRaises(CGroupsException):
                CGroupConfigurator.get_instance().enable()

    def test_cgroup_operations_should_not_invoke_the_cgroup_api_when_cgroups_are_not_enabled(self):
        configurator = CGroupConfigurator.get_instance()
        configurator.disable()

        # List of operations to test, and the functions to mock used in order to do verifications
        operations = [
            [lambda: configurator.create_agent_cgroups(track_cgroups=False), "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_agent_cgroups"],
            [lambda: configurator.create_extension_cgroups_root(),           "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_extension_cgroups_root"],
            [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_extension_cgroups"],
            [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.remove_extension_cgroups"]
        ]

        for op in operations:
            with patch(op[1]) as mock_cgroup_api_operation:
                op[0]()

            self.assertEqual(mock_cgroup_api_operation.call_count, 0)

    def test_cgroup_operations_should_log_a_warning_when_the_cgroup_api_raises_an_exception(self):
        configurator = CGroupConfigurator.get_instance()

        # List of operations to test, and the functions to mock in order to raise exceptions
        operations = [
            [lambda: configurator.create_agent_cgroups(track_cgroups=False), "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_agent_cgroups"],
            [lambda: configurator.create_extension_cgroups_root(),           "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_extension_cgroups_root"],
            [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.create_extension_cgroups"],
            [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.remove_extension_cgroups"]
        ]

        def raise_exception(*_):
            raise Exception("A TEST EXCEPTION")

        for op in operations:
            with patch("azurelinuxagent.common.cgroupconfigurator.logger.warn") as mock_logger_warn:
                with patch(op[1], raise_exception):
                    op[0]()

                self.assertEquals(mock_logger_warn.call_count, 1)

                args, kwargs = mock_logger_warn.call_args
                message = args[0]
                self.assertIn("A TEST EXCEPTION", message)

    def test_start_extension_command_should_forward_to_subprocess_popen_when_groups_are_not_enabled(self):
        configurator = CGroupConfigurator.get_instance()
        configurator.disable()

        with patch("azurelinuxagent.common.cgroupconfigurator.subprocess.Popen") as mock_popen:
            configurator.start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="date",
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            self.assertEqual(mock_popen.call_count, 1)

    def test_start_extension_command_should_forward_to_cgroups_api_when_groups_are_enabled(self):
        configurator = CGroupConfigurator.get_instance()

        with patch("azurelinuxagent.common.cgroupapi.FileSystemCgroupsApi.start_extension_command") as mock_start_extension_command:
            configurator.start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="date",
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            self.assertEqual(mock_start_extension_command.call_count, 1)
