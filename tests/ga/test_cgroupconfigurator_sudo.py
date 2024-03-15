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
import subprocess
import tempfile

from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from tests.lib.mock_cgroup_environment import mock_cgroup_v1_environment
from tests.lib.tools import AgentTestCase, patch, mock_sleep, i_am_root, is_python_version_26_or_34, skip_if_predicate_true


class CGroupConfiguratorSystemdTestCaseSudo(AgentTestCase):
    @classmethod
    def tearDownClass(cls):
        CGroupConfigurator._instance = None
        AgentTestCase.tearDownClass()

    @contextlib.contextmanager
    def _get_cgroup_configurator(self, initialize=True, enable=True, mock_commands=None):
        CGroupConfigurator._instance = None
        configurator = CGroupConfigurator.get_instance()
        CGroupsTelemetry.reset()
        with mock_cgroup_v1_environment(self.tmp_dir) as mock_environment:
            if mock_commands is not None:
                for command in mock_commands:
                    mock_environment.add_command(command)
            configurator.mocks = mock_environment
            if initialize:
                if not enable:
                    with patch.object(configurator, "enable"):
                        configurator.initialize()
                else:
                    configurator.initialize()
            yield configurator

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        command = "ls folder_does_not_exist"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=command,
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # The scope name should appear in the process output since systemd-run was invoked and stderr
                    # wasn't truncated.
                    self.assertIn("Running scope as unit", ustr(context_manager.exception))

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    @patch("azurelinuxagent.ga.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN", 5)
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails_with_long_output(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        long_output = "a"*20  # large enough to ensure both stdout and stderr are truncated
        long_stdout_stderr_command = "echo {0} && echo {0} >&2 && ls folder_does_not_exist".format(long_output)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=long_stdout_stderr_command,
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if long_stdout_stderr_command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # stdout and stderr should have been truncated, so the scope name doesn't appear in stderr
                    # even though systemd-run ran
                    self.assertNotIn("Running scope as unit", ustr(context_manager.exception))

    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args):  # pylint: disable=unused-argument
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.extensionprocessutil.wait_for_process_completion_or_timeout",
                           return_value=[True, None, 0]):
                    with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi._is_systemd_failure",
                               return_value=False):
                        with self.assertRaises(ExtensionError) as context_manager:
                            configurator.start_extension_command(
                                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                                command="date",
                                cmd_name="test",
                                timeout=300,
                                shell=True,
                                cwd=self.tmp_dir,
                                env={},
                                stdout=stdout,
                                stderr=stderr)

                        self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginHandlerScriptTimedout)
                        self.assertIn("Timeout", ustr(context_manager.exception))
