# Copyright Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#
from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.extensionprocessutil import format_stdout_stderr, read_output, \
    wait_for_process_completion_or_timeout, handle_process_completion
from tests.tools import AgentTestCase, patch
import os # pylint: disable=wrong-import-order
import shutil # pylint: disable=wrong-import-order
import subprocess # pylint: disable=wrong-import-order
import tempfile # pylint: disable=wrong-import-order


class TestProcessUtils(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.tmp_dir = tempfile.mkdtemp()
        self.stdout = tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b")
        self.stderr = tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b")

        self.stdout.write("The quick brown fox jumps over the lazy dog.".encode("utf-8"))
        self.stderr.write("The five boxing wizards jump quickly.".encode("utf-8"))

    def tearDown(self):
        if self.tmp_dir is not None:
            shutil.rmtree(self.tmp_dir)

    def test_wait_for_process_completion_or_timeout_should_terminate_cleanly(self):
        process = subprocess.Popen(
            "date",
            shell=True,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        timed_out, ret = wait_for_process_completion_or_timeout(process=process, timeout=5)
        self.assertEqual(timed_out, False) 
        self.assertEqual(ret, 0) 

    def test_wait_for_process_completion_or_timeout_should_kill_process_on_timeout(self):
        timeout = 5
        process = subprocess.Popen( # pylint: disable=subprocess-popen-preexec-fn
            "sleep 1m",
            shell=True,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid)

        # We don't actually mock the kill, just wrap it so we can assert its call count
        with patch('azurelinuxagent.common.utils.extensionprocessutil.os.killpg', wraps=os.killpg) as patch_kill:
            with patch('time.sleep') as mock_sleep:
                timed_out, ret = wait_for_process_completion_or_timeout(process=process, timeout=timeout)

                # We're mocking sleep to avoid prolonging the test execution time, but we still want to make sure
                # we're "waiting" the correct amount of time before killing the process
                self.assertEqual(mock_sleep.call_count, timeout) 

                self.assertEqual(patch_kill.call_count, 1) 
                self.assertEqual(timed_out, True) 
                self.assertEqual(ret, None) 

    def test_handle_process_completion_should_return_nonzero_when_process_fails(self):
        process = subprocess.Popen(
            "ls folder_does_not_exist",
            shell=True,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        timed_out, ret = wait_for_process_completion_or_timeout(process=process, timeout=5)
        self.assertEqual(timed_out, False) 
        self.assertEqual(ret, 2) 

    def test_handle_process_completion_should_return_process_output(self):
        command = "echo 'dummy stdout' && 1>&2 echo 'dummy stderr'"
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                process = subprocess.Popen(command, # pylint: disable=subprocess-popen-preexec-fn
                                           shell=True,
                                           cwd=self.tmp_dir,
                                           env={},
                                           stdout=stdout,
                                           stderr=stderr,
                                           preexec_fn=os.setsid)

                process_output = handle_process_completion(process=process,
                                                           command=command,
                                                           timeout=5,
                                                           stdout=stdout,
                                                           stderr=stderr,
                                                           error_code=42)

        expected_output = "[stdout]\ndummy stdout\n\n\n[stderr]\ndummy stderr\n"
        self.assertEqual(process_output, expected_output) 

    def test_handle_process_completion_should_raise_on_timeout(self):
        command = "sleep 1m"
        timeout = 20
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch('time.sleep') as mock_sleep:
                    with self.assertRaises(ExtensionError) as context_manager:
                        process = subprocess.Popen(command, # pylint: disable=subprocess-popen-preexec-fn
                                                   shell=True,
                                                   cwd=self.tmp_dir,
                                                   env={},
                                                   stdout=stdout,
                                                   stderr=stderr,
                                                   preexec_fn=os.setsid)

                        handle_process_completion(process=process,
                                                  command=command,
                                                  timeout=timeout,
                                                  stdout=stdout,
                                                  stderr=stderr,
                                                  error_code=42)

                    # We're mocking sleep to avoid prolonging the test execution time, but we still want to make sure
                    # we're "waiting" the correct amount of time before killing the process and raising an exception
                    # Due to an extra call to sleep at some point in the call stack which only happens sometimes,
                    # we are relaxing this assertion to allow +/- 2 sleep calls.
                    self.assertTrue(abs(mock_sleep.call_count - timeout) <= 2)

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginHandlerScriptTimedout)
                    self.assertIn("Timeout({0})".format(timeout), ustr(context_manager.exception))

    def test_handle_process_completion_should_raise_on_nonzero_exit_code(self):
        command = "ls folder_does_not_exist"
        error_code = 42
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with self.assertRaises(ExtensionError) as context_manager:
                    process = subprocess.Popen(command, # pylint: disable=subprocess-popen-preexec-fn
                                               shell=True,
                                               cwd=self.tmp_dir,
                                               env={},
                                               stdout=stdout,
                                               stderr=stderr,
                                               preexec_fn=os.setsid)

                    handle_process_completion(process=process,
                                              command=command,
                                              timeout=4,
                                              stdout=stdout,
                                              stderr=stderr,
                                              error_code=error_code)

                self.assertEqual(context_manager.exception.code, error_code) 
                self.assertIn("Non-zero exit code:", ustr(context_manager.exception))

    def test_read_output_should_return_no_content(self):
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 0):
            expected = ""
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)

    def test_read_output_should_truncate_the_content(self):
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 50):
            expected = "[stdout]\nr the lazy dog.\n\n" \
                       "[stderr]\ns jump quickly."
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)

    def test_read_output_should_not_truncate_the_content(self):
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 90):
            expected = "[stdout]\nThe quick brown fox jumps over the lazy dog.\n\n" \
                       "[stderr]\nThe five boxing wizards jump quickly."
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)


    def test_format_stdout_stderr00(self):
        """
        If stdout and stderr are both smaller than the max length,
        the full representation should be displayed.
        """
        stdout = "The quick brown fox jumps over the lazy dog."
        stderr = "The five boxing wizards jump quickly."

        expected = "[stdout]\n{0}\n\n[stderr]\n{1}".format(stdout, stderr)
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 1000):
            actual = format_stdout_stderr(stdout, stderr)
            self.assertEqual(expected, actual)

    def test_format_stdout_stderr01(self):
        """
        If stdout and stderr both exceed the max length,
        then both stdout and stderr are trimmed equally.
        """
        stdout = "The quick brown fox jumps over the lazy dog."
        stderr = "The five boxing wizards jump quickly."

        # noinspection SpellCheckingInspection
        expected = '[stdout]\ns over the lazy dog.\n\n[stderr]\nizards jump quickly.'
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 60):
            actual = format_stdout_stderr(stdout, stderr)
            self.assertEqual(expected, actual)
            self.assertEqual(60, len(actual))

    def test_format_stdout_stderr02(self):
        """
        If stderr is much larger than stdout, stderr is allowed
        to borrow space from stdout's quota.
        """
        stdout = "empty"
        stderr = "The five boxing wizards jump quickly."

        expected = '[stdout]\nempty\n\n[stderr]\ns jump quickly.'
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 40):
            actual = format_stdout_stderr(stdout, stderr)
            self.assertEqual(expected, actual)
            self.assertEqual(40, len(actual))

    def test_format_stdout_stderr03(self):
        """
        If stdout is much larger than stderr, stdout is allowed
        to borrow space from stderr's quota.
        """
        stdout = "The quick brown fox jumps over the lazy dog."
        stderr = "empty"

        expected = '[stdout]\nr the lazy dog.\n\n[stderr]\nempty'
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 40):
            actual = format_stdout_stderr(stdout, stderr)
            self.assertEqual(expected, actual)
            self.assertEqual(40, len(actual))

    def test_format_stdout_stderr04(self):
        """
        If the max length is not sufficient to even hold the stdout
        and stderr markers an empty string is returned.
        """
        stdout = "The quick brown fox jumps over the lazy dog."
        stderr = "The five boxing wizards jump quickly."

        expected = ''
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 4):
            actual = format_stdout_stderr(stdout, stderr)
            self.assertEqual(expected, actual)
            self.assertEqual(0, len(actual))

    def test_format_stdout_stderr05(self):
        """
        If stdout and stderr are empty, an empty template is returned.
        """

        expected = '[stdout]\n\n\n[stderr]\n'
        with patch('azurelinuxagent.common.utils.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN', 1000):
            actual = format_stdout_stderr('', '')
            self.assertEqual(expected, actual)
