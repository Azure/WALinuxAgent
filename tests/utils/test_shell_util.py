# -*- coding: utf-8 -*-
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
# Requires Python 2.6+ and Openssl 1.0+
#
from tests.tools import AgentTestCase, patch
import unittest # pylint: disable=wrong-import-order
import azurelinuxagent.common.utils.shellutil as shellutil


class ShellQuoteTestCase(AgentTestCase):
    def test_shellquote(self):
        self.assertEqual("\'foo\'", shellutil.quote("foo"))
        self.assertEqual("\'foo bar\'", shellutil.quote("foo bar"))
        self.assertEqual("'foo'\\''bar'", shellutil.quote("foo\'bar"))


class RunTestCase(AgentTestCase):
    def test_it_should_return_the_exit_code_of_the_command(self):
        exit_code = shellutil.run("exit 123")
        self.assertEqual(123, exit_code)

    def test_it_should_be_a_pass_thru_to_run_get_output(self):
        with patch.object(shellutil, "run_get_output", return_value=(0, "")) as mock_run_get_output:
            shellutil.run("echo hello word!", chk_err=False, expected_errors=[1, 2, 3])

        self.assertEqual(mock_run_get_output.call_count, 1)

        args, kwargs = mock_run_get_output.call_args
        self.assertEqual(args[0], "echo hello word!")
        self.assertEqual(kwargs["chk_err"], False)
        self.assertEqual(kwargs["expected_errors"], [1, 2, 3])


class RunGetOutputTestCase(AgentTestCase):
    def test_run_get_output(self):
        output = shellutil.run_get_output(u"ls /")
        self.assertNotEqual(None, output)
        self.assertEqual(0, output[0])

        err = shellutil.run_get_output(u"ls /not-exists")
        self.assertNotEqual(0, err[0])
            
        err = shellutil.run_get_output(u"ls 我")
        self.assertNotEqual(0, err[0])

    def test_it_should_log_the_command(self):
        command = "echo hello world!"

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command)

        self.assertEqual(mock_logger.verbose.call_count, 1)

        args, kwargs = mock_logger.verbose.call_args # pylint: disable=unused-variable
        command_in_message = args[1]
        self.assertEqual(command_in_message, command)

    def test_it_should_log_command_failures_as_errors(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False)

        self.assertEqual(mock_logger.error.call_count, 1)

        args, kwargs = mock_logger.error.call_args # pylint: disable=unused-variable

        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEqual(mock_logger.verbose.call_count, 0)
        self.assertEqual(mock_logger.info.call_count, 0)
        self.assertEqual(mock_logger.warn.call_count, 0)

    def test_it_should_log_expected_errors_as_info(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False, expected_errors=[return_code])

        self.assertEqual(mock_logger.info.call_count, 1)

        args, kwargs = mock_logger.info.call_args # pylint: disable=unused-variable

        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEqual(mock_logger.verbose.call_count, 0)
        self.assertEqual(mock_logger.warn.call_count, 0)
        self.assertEqual(mock_logger.error.call_count, 0)

    def test_it_should_log_unexpected_errors_as_errors(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False, expected_errors=[return_code + 1])

        self.assertEqual(mock_logger.error.call_count, 1)

        args, kwargs = mock_logger.error.call_args # pylint: disable=unused-variable

        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEqual(mock_logger.info.call_count, 0)
        self.assertEqual(mock_logger.verbose.call_count, 0)
        self.assertEqual(mock_logger.warn.call_count, 0)


class RunCommandTestCase(AgentTestCase):
    def test_run_command_should_execute_the_command(self):
        command = ["echo", "-n", "A TEST STRING"]
        ret = shellutil.run_command(command)
        self.assertEqual(ret, "A TEST STRING")

    def test_run_command_should_raise_an_exception_when_the_command_fails(self):
        command = ["ls", "-d", "/etc", "nonexistent_file"]

        with self.assertRaises(shellutil.CommandError) as context_manager:
            shellutil.run_command(command)

        exception = context_manager.exception
        self.assertIn("'ls' failed: 2", str(exception))
        self.assertIn("No such file or directory", str(exception))
        self.assertEqual(exception.stdout, "/etc\n")
        self.assertIn("No such file or directory", exception.stderr)
        self.assertEqual(exception.returncode, 2)

    def test_run_command_should_raise_an_exception_when_it_cannot_execute_the_command(self):
        command = "nonexistent_command"

        with self.assertRaises(Exception) as context_manager:
            shellutil.run_command(command)

        exception = context_manager.exception
        self.assertIn("No such file or directory", str(exception))

    @patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True)
    def test_run_command_it_should_not_log_by_default(self, mock_logger):

        def assert_no_message_logged(command):
            try:
                shellutil.run_command(command)
            except: # pylint: disable=bare-except
                pass

            self.assertEqual(mock_logger.info.call_count, 0)
            self.assertEqual(mock_logger.verbose.call_count, 0)
            self.assertEqual(mock_logger.warn.call_count, 0)
            self.assertEqual(mock_logger.error.call_count, 0)

            assert_no_message_logged(["ls", "nonexistent_file"])
            assert_no_message_logged("nonexistent_command")

    def test_run_command_it_should_log_an_error_when_log_error_is_set(self):
        command = ["ls", "-d", "/etc", "nonexistent_file"]

        with patch("azurelinuxagent.common.utils.shellutil.logger.error") as mock_log_error:
            try:
                shellutil.run_command(command, log_error=True)
            except: # pylint: disable=bare-except
                pass

            self.assertEqual(mock_log_error.call_count, 1)

            args, kwargs = mock_log_error.call_args # pylint: disable=unused-variable
            self.assertIn("ls -d /etc nonexistent_file", args, msg="The command was not logged")
            self.assertIn(2, args, msg="The command's return code was not logged")
            self.assertIn("/etc\n", args, msg="The command's stdout was not logged")
            self.assertTrue(any("No such file or directory" in str(a) for a in args), msg="The command's stderr was not logged")

        command = "nonexistent_command"

        with patch("azurelinuxagent.common.utils.shellutil.logger.error") as mock_log_error:
            try:
                shellutil.run_command(command, log_error=True)
            except: # pylint: disable=bare-except
                pass

            self.assertEqual(mock_log_error.call_count, 1)

            args, kwargs = mock_log_error.call_args
            self.assertIn(command, args, msg="The command was not logged")
            self.assertTrue(any("No such file or directory" in str(a) for a in args), msg="The command's stderr was not logged")

    def test_run_command_it_should_read_from_stdin_if_cmd_input_is_set(self):
        import random
        command = ["cat"]
        random_hash = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
        try:
            output = shellutil.run_command(command, cmd_input=random_hash)
        except: # pylint: disable=bare-except
            self.fail("No exception should've been thrown when trying to read from stdin in run_command")

        self.assertEqual(output, random_hash, "We're reading from stdin and printing it shell, output should match")


if __name__ == '__main__':
    unittest.main()
