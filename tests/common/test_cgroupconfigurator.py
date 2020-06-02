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
import subprocess

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import CGroupsException
from tests.common.mock_cgroup_commands import mock_cgroup_commands
from tests.tools import AgentTestCase, patch


class CGroupConfiguratorSystemdTestCase(AgentTestCase):
    @classmethod
    def tearDownClass(cls):
        CGroupConfigurator._instance = None
        AgentTestCase.tearDownClass()

    @staticmethod
    def _get_new_cgroup_configurator_instance(initialize=True):
        CGroupConfigurator._instance = None
        configurator = CGroupConfigurator.get_instance()
        if initialize:
            with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported', return_value=True):
                with patch('azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd', return_value=True):
                    with mock_cgroup_commands():
                        configurator.initialize()
        return configurator

    def test_initialize_should_start_tracking_the_agent_cgroups(self):
        CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        tracked = CGroupsTelemetry._tracked

        self.assertTrue(
            any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'cpu' in cg.path),
            "The Agent's CPU is not being tracked")
        self.assertTrue(
            any(cg for cg in tracked if cg.name == 'walinuxagent.service' and 'memory' in cg.path),
            "The Agent's memory is not being tracked")

    def test_enable_and_disable_should_change_the_enabled_state_of_cgroups(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        self.assertTrue(configurator.enabled(), "CGroupConfigurator should be enabled by default")

        configurator.disable()
        self.assertFalse(configurator.enabled(), "disable() should disable the CGroupConfigurator")

        configurator.enable()
        self.assertTrue(configurator.enabled(), "enable() should enable the CGroupConfigurator")

    def test_enable_should_raise_CGroupsException_when_cgroups_are_not_supported(self):
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

        self.assertEquals(len(CGroupsTelemetry._tracked), 0)

    def test_cgroup_operations_should_not_invoke_the_cgroup_api_when_cgroups_are_not_enabled(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()
        configurator.disable()

        # List of operations to test, and the functions to mock used in order to do verifications
        operations = [
            [lambda: configurator.create_extension_cgroups_root(),           "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups_root"],
            [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups"],
            [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.remove_extension_cgroups"]
        ]

        for op in operations:
            with patch(op[1]) as mock_cgroup_api_operation:
                op[0]()

            self.assertEqual(mock_cgroup_api_operation.call_count, 0)

    def test_cgroup_operations_should_log_a_warning_when_the_cgroup_api_raises_an_exception(self):
        configurator = CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance()

        # cleanup_legacy_cgroups disables cgroups on error, so make disable() a no-op
        with patch.object(configurator, "disable"):
            # List of operations to test, and the functions to mock in order to raise exceptions
            operations = [
                [lambda: configurator.create_extension_cgroups_root(),           "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups_root"],
                [lambda: configurator.create_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.create_extension_cgroups"],
                [lambda: configurator.remove_extension_cgroups("A.B.C-1.0.0"),   "azurelinuxagent.common.cgroupapi.SystemdCgroupsApi.remove_extension_cgroups"]
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

    def test_start_extension_command_should_not_use_systemd_when_groups_are_not_enabled(self):
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

    @staticmethod
    @contextlib.contextmanager
    def _create_mock_popen(command):
        """
         Creates a mock for subprocess.Popen that replaces the given command with a dummy command (date); this allows
        the tests below to run  on environments where systemd-run is not available
        """
        original_popen = subprocess.Popen

        def mock_popen(command_arg, *args, **kwargs):
            if command in command_arg:
                return original_popen("date", *args, **kwargs)
            else:
                return original_popen(command_arg, *args, **kwargs)

        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patcher:
            patcher.get_command_calls = lambda: [args[0] for args, _ in patcher.call_args_list if len(args) > 0 and command in args[0]]
            yield patcher

    def test_start_extension_command_should_use_systemd_run_when_groups_are_enabled(self):
        with CGroupConfiguratorSystemdTestCase._create_mock_popen("test command") as patch_popen:
            CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                timeout=300,
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            command_calls = patch_popen.get_command_calls()
            self.assertEqual(len(command_calls), 1, "The test command should have been called exactly once [{0}]".format(command_calls))
            self.assertTrue(command_calls[0].startswith("systemd-run"), "The command should have been invoked using systemd [{0}]".format(command_calls))

    def test_start_extension_command_should_start_tracking_the_extension_cgroups(self):
        # CPU usage is initialized when we begin tracking a CPU cgroup; since this test does not retrieve the
        # CPU usage, there is no need for initialization
        with CGroupConfiguratorSystemdTestCase._create_mock_popen("test command") as patch_popen:
            CGroupConfiguratorSystemdTestCase._get_new_cgroup_configurator_instance().start_extension_command(
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

        with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patcher:
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

