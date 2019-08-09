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

from tests.tools import *
import unittest
import azurelinuxagent.common.utils.shellutil as shellutil


class ShellQuoteTestCase(AgentTestCase):
    def test_shellquote(self):
        self.assertEqual("\'foo\'", shellutil.quote("foo"))
        self.assertEqual("\'foo bar\'", shellutil.quote("foo bar"))
        self.assertEqual("'foo'\\''bar'", shellutil.quote("foo\'bar"))


class RunTestCase(AgentTestCase):
    def test_it_should_return_the_exit_code_of_the_command(self):
        exit_code = shellutil.run("exit 123")
        self.assertEquals(123, exit_code)

    def test_it_should_be_a_pass_thru_to_run_get_output(self):
        with patch.object(shellutil, "run_get_output", return_value=(0, "")) as mock_run_get_output:
            shellutil.run("echo hello word!", chk_err=False, expected_errors=[1, 2, 3])

        self.assertEquals(mock_run_get_output.call_count, 1)

        args, kwargs = mock_run_get_output.call_args
        self.assertEquals(args[0], "echo hello word!")
        self.assertEquals(kwargs["chk_err"], False)
        self.assertEquals(kwargs["expected_errors"], [1, 2, 3])


class RunGetOutputTestCase(AgentTestCase):
    def test_run_get_output(self):
        output = shellutil.run_get_output(u"ls /")
        self.assertNotEquals(None, output)
        self.assertEquals(0, output[0])

        err = shellutil.run_get_output(u"ls /not-exists")
        self.assertNotEquals(0, err[0])
            
        err = shellutil.run_get_output(u"ls 我")
        self.assertNotEquals(0, err[0])

    def test_it_should_log_the_command(self):
        command = "echo hello world!"

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command)

        self.assertEquals(mock_logger.verbose.call_count, 1)

        args, kwargs = mock_logger.verbose.call_args
        command_in_message = args[1]
        self.assertEqual(command_in_message, command)

    def test_it_should_log_command_failures_as_errors(self):
        logger_delta = str("logger.EVERY_FIFTEEN_MINUTES")
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False)

        self.assertEquals(mock_logger.periodic_error.call_count, 1)

        args, kwargs = mock_logger.periodic_error.call_args

        time_delta = str(args[0])
        self.assertIn(logger_delta, time_delta)

        message = args[1]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEquals(mock_logger.verbose.call_count, 0)
        self.assertEquals(mock_logger.info.call_count, 0)
        self.assertEquals(mock_logger.warn.call_count, 0)

    def test_it_should_log_expected_errors_as_info(self):
        logger_delta = str("logger.EVERY_FIFTEEN_MINUTES")
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False, expected_errors=[return_code])

        self.assertEquals(mock_logger.periodic_info.call_count, 1)

        args, kwargs = mock_logger.periodic_info.call_args

        time_delta = str(args[0])
        self.assertIn(logger_delta, time_delta)

        message = args[1]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEquals(mock_logger.verbose.call_count, 0)
        self.assertEquals(mock_logger.warn.call_count, 0)
        self.assertEquals(mock_logger.error.call_count, 0)

    def test_it_should_log_unexpected_errors_as_errors(self):
        logger_delta = str("logger.EVERY_FIFTEEN_MINUTES")
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False, expected_errors=[return_code + 1])

        self.assertEquals(mock_logger.periodic_error.call_count, 1)

        args, kwargs = mock_logger.periodic_error.call_args

        time_delta = str(args[0])
        self.assertIn(logger_delta, time_delta)

        message = args[1]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEquals(mock_logger.info.call_count, 0)
        self.assertEquals(mock_logger.verbose.call_count, 0)
        self.assertEquals(mock_logger.warn.call_count, 0)


class RunCommandTestCase(AgentTestCase):
    def test_run_command_it_should_run_without_errors(self):
        command = ["echo", "42"]

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            ret = shellutil.run_command(command)
            self.assertEquals(ret, "42\n")
            self.assertEquals(mock_logger.error.call_count, 0)

    def test_run_command_it_should_log_and_raise_an_exception_from_command(self):
        command = ["ls", "nonexistent_file"]
        expected_returncode = 2

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            with self.assertRaises(Exception) as context_manager:
                shellutil.run_command(command)

            ex = context_manager.exception
            exception_message = u"Command [{0}] failed with return code [{1}]".format(command, expected_returncode)
            self.assertEquals(exception_message, ex.message)

            self.assertEquals(mock_logger.error.call_count, 1)

            logged_error_message = u"Command: [{0}], return code: [{1}]".format(command, expected_returncode)
            self.assertIn(logged_error_message, mock_logger.error.call_args_list[0][0][0])

    def test_run_command_it_should_log_and_raise_an_exception_from_invoking_command(self):
        command = "nonexistent_command"

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            with self.assertRaises(Exception):
                shellutil.run_command(command)

            self.assertEquals(mock_logger.error.call_count, 1)

            logged_error_message = u"Cannot execute [{0}]. Error: [{1}]".format(command,
                                                                                "[Errno 2] No such file or directory")
            self.assertIn(logged_error_message, mock_logger.error.call_args_list[0][0][0])


if __name__ == '__main__':
    unittest.main()
