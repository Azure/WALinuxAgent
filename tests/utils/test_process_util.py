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
from azurelinuxagent.common.utils.processutil import format_stdout_stderr, read_output, \
    wait_for_process_completion_or_timeout, start_subprocess_and_wait_for_completion
from tests.tools import *
import subprocess


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

        timed_out, ret = wait_for_process_completion_or_timeout(process, 5)
        self.assertEquals(timed_out, False)
        self.assertEquals(ret, 0)

    def test_wait_for_process_completion_or_timeout_should_kill_process_on_timeout(self):
        process = subprocess.Popen(
            "sleep 4s",
            shell=True,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid)

        with patch('azurelinuxagent.common.utils.processutil.os.killpg') as mock_kill:
            timed_out, ret = wait_for_process_completion_or_timeout(process, 2)

            self.assertEquals(mock_kill.call_count, 1)
            self.assertEquals(timed_out, True)
            self.assertEquals(ret, None)

    def test_wait_for_process_completion_or_timeout_should_return_nonzero_return_code(self):
        process = subprocess.Popen(
            "ls folder_does_not_exist",
            shell=True,
            cwd=self.tmp_dir,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        timed_out, ret = wait_for_process_completion_or_timeout(process, 5)
        self.assertEquals(timed_out, False)
        self.assertEquals(ret, 2)

    def test_start_subprocess_and_wait_for_completion_should_return_process_output(self):
        command = "echo 'dummy output'"
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                process_output = start_subprocess_and_wait_for_completion(command=command,
                                                                          timeout=5,
                                                                          shell=True,
                                                                          cwd=self.tmp_dir,
                                                                          env={},
                                                                          stdout=stdout,
                                                                          stderr=stderr,
                                                                          preexec_fn=os.setsid,
                                                                          error_code=42)
        expected_output = "[stdout]\ndummy output\n\n\n[stderr]\n"
        self.assertEquals(process_output, expected_output)

    def test_start_subprocess_and_wait_for_completion_should_raise_on_timeout(self):
        command = "sleep 4s"
        timeout = 2
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with self.assertRaises(ExtensionError) as context_manager:
                    start_subprocess_and_wait_for_completion(command=command,
                                                             timeout=timeout,
                                                             shell=True,
                                                             cwd=self.tmp_dir,
                                                             env={},
                                                             stdout=stdout,
                                                             stderr=stderr,
                                                             preexec_fn=os.setsid,
                                                             error_code=42)
                self.assertEquals(context_manager.exception.code, ExtensionErrorCodes.PluginHandlerScriptTimedout)
                self.assertIn("Timeout({0})".format(timeout), ustr(context_manager.exception))

    def test_start_subprocess_and_wait_for_completion_should_raise_on_nonzero_exit_code(self):
        command = "ls folder_does_not_exist"
        error_code = 42
        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with self.assertRaises(ExtensionError) as context_manager:
                    start_subprocess_and_wait_for_completion(command=command,
                                                             timeout=4,
                                                             shell=True,
                                                             cwd=self.tmp_dir,
                                                             env={},
                                                             stdout=stdout,
                                                             stderr=stderr,
                                                             preexec_fn=os.setsid,
                                                             error_code=error_code)
                self.assertEquals(context_manager.exception.code, error_code)
                self.assertIn("Non-zero exit code:", ustr(context_manager.exception))

    def test_read_output_it_should_return_no_content(self):
        with patch('azurelinuxagent.common.utils.processutil.TELEMETRY_MESSAGE_MAX_LEN', 0):
            expected = "[stdout]\n\n\n[stderr]\n"
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)

    def test_read_output_it_should_truncate_the_content(self):
        with patch('azurelinuxagent.common.utils.processutil.TELEMETRY_MESSAGE_MAX_LEN', 10):
            expected = "[stdout]\nThe quick \n\n[stderr]\nThe five b"
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)

    def test_read_output_it_should_return_all_content(self):
        with patch('azurelinuxagent.common.utils.processutil.TELEMETRY_MESSAGE_MAX_LEN', 50):
            expected = "[stdout]\nThe quick brown fox jumps over the lazy dog.\n\n" \
                       "[stderr]\nThe five boxing wizards jump quickly."
            actual = read_output(self.stdout, self.stderr)
            self.assertEqual(expected, actual)

    def test_read_output_it_should_handle_exceptions(self):
        with patch('azurelinuxagent.common.utils.processutil.TELEMETRY_MESSAGE_MAX_LEN', "type error"):
            actual = read_output(self.stdout, self.stderr)
            self.assertIn("Cannot read stdout/stderr", actual)

    def test_format_stdout_stderr00(self):
        """
        If stdout and stderr are both smaller than the max length,
        the full representation should be displayed.
        """
        stdout = "The quick brown fox jumps over the lazy dog."
        stderr = "The five boxing wizards jump quickly."

        expected = "[stdout]\n{0}\n\n[stderr]\n{1}".format(stdout, stderr)
        actual = format_stdout_stderr(stdout, stderr, 1000)
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
        actual = format_stdout_stderr(stdout, stderr, 60)
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
        actual = format_stdout_stderr(stdout, stderr, 40)
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
        actual = format_stdout_stderr(stdout, stderr, 40)
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
        actual = format_stdout_stderr(stdout, stderr, 4)
        self.assertEqual(expected, actual)
        self.assertEqual(0, len(actual))

    def test_format_stdout_stderr05(self):
        """
        If stdout and stderr are empty, an empty template is returned.
        """

        expected = '[stdout]\n\n\n[stderr]\n'
        actual = format_stdout_stderr('', '', 1000)
        self.assertEqual(expected, actual)
