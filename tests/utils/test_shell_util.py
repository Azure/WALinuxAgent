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
import datetime
import os
import signal
import tempfile
import threading
import time
import unittest

from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.utils.shellutil as shellutil
from tests.tools import AgentTestCase, patch


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

        args, kwargs = mock_logger.verbose.call_args  # pylint: disable=unused-variable
        command_in_message = args[1]
        self.assertEqual(command_in_message, command)

    def test_it_should_log_command_failures_as_errors(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            shellutil.run_get_output(command, log_cmd=False)

        self.assertEqual(mock_logger.error.call_count, 1)

        args, kwargs = mock_logger.error.call_args  # pylint: disable=unused-variable

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

        args, kwargs = mock_logger.info.call_args  # pylint: disable=unused-variable

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

        args, kwargs = mock_logger.error.call_args  # pylint: disable=unused-variable

        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

        self.assertEqual(mock_logger.info.call_count, 0)
        self.assertEqual(mock_logger.verbose.call_count, 0)
        self.assertEqual(mock_logger.warn.call_count, 0)


# R0904: Too many public methods (24/20)  -- disabled: each method is a unit test
class RunCommandTestCase(AgentTestCase):  # pylint: disable=R0904
    """
    Tests for shellutil.run_command/run_pipe
    """
    def __create_tee_script(self, return_code=0):
        """
        Creates a Python script that tees its stdin to stdout and stderr
        """
        tee_script = os.path.join(self.tmp_dir, "tee.py")

        AgentTestCase.create_script(tee_script, """
import sys

for line in sys.stdin:
    sys.stdout.write(line)
    sys.stderr.write(line)
exit({0})
    """.format(return_code))

        return tee_script

    def test_run_command_should_execute_the_command(self):
        command = ["echo", "-n", "A TEST STRING"]
        ret = shellutil.run_command(command)
        self.assertEqual(ret, "A TEST STRING")

    def test_run_pipe_should_execute_a_pipe_with_two_commands(self):
        # Output the same string 3 times and then remove duplicates
        test_string = "A TEST STRING\n"
        pipe = [["echo", "-n", "-e", test_string * 3], ["uniq"]]

        output = shellutil.run_pipe(pipe)

        self.assertEqual(output, test_string)

    def test_run_pipe_should_execute_a_pipe_with_more_than_two_commands(self):
        #
        # The test pipe splits the output of "ls" in lines and then greps for "."
        #
        # Sample output of "ls -d .":
        #     drwxrwxr-x 13 nam nam 4096 Nov 13 16:54 .
        #
        pipe = [["ls", "-ld", "."], ["sed", "-r", "s/\\s+/\\n/g"], ["grep", "\\."]]

        output = shellutil.run_pipe(pipe)

        self.assertEqual(".\n", output, "The pipe did not produce the expected output. Got: {0}".format(output))

    def __it_should_raise_an_exception_when_the_command_fails(self, action):
        with self.assertRaises(shellutil.CommandError) as context_manager:
            action()

        exception = context_manager.exception
        self.assertIn("tee.py", str(exception), "The CommandError does not include the expected command")
        self.assertEqual(1, exception.returncode, "Unexpected return value from the test pipe")
        self.assertEqual("TEST_STRING\n", exception.stdout, "Unexpected stdout from the test pipe")
        self.assertEqual("TEST_STRING\n", exception.stderr, "Unexpected stderr from the test pipe")

    def test_run_command_should_raise_an_exception_when_the_command_fails(self):
        tee_script = self.__create_tee_script(return_code=1)

        self.__it_should_raise_an_exception_when_the_command_fails(
            lambda: shellutil.run_command(tee_script, input="TEST_STRING\n"))

    def test_run_pipe_should_raise_an_exception_when_the_last_command_fails(self):
        tee_script = self.__create_tee_script(return_code=1)

        self.__it_should_raise_an_exception_when_the_command_fails(
            lambda: shellutil.run_pipe([["echo", "-n", "TEST_STRING\n"], [tee_script]]))

    def __it_should_raise_an_exception_when_it_cannot_execute_the_command(self, action):
        with self.assertRaises(Exception) as context_manager:
            action()

        exception = context_manager.exception
        self.assertIn("No such file or directory", str(exception))

    def test_run_command_should_raise_an_exception_when_it_cannot_execute_the_command(self):
        self.__it_should_raise_an_exception_when_it_cannot_execute_the_command(
            lambda: shellutil.run_command("nonexistent_command"))

    def test_run_pipe_should_raise_an_exception_when_it_cannot_execute_the_pipe(self):
        self.__it_should_raise_an_exception_when_it_cannot_execute_the_command(
            lambda: shellutil.run_pipe([["ls", "-ld", "."], ["nonexistent_command"], ["wc", "-l"]]))

    def __it_should_not_log_by_default(self, action):
        with patch("azurelinuxagent.common.utils.shellutil.logger", autospec=True) as mock_logger:
            try:
                action()
            except Exception:
                pass

            self.assertEqual(mock_logger.warn.call_count, 0, "Did not expect any WARNINGS; Got: {0}".format(mock_logger.warn.call_args))
            self.assertEqual(mock_logger.error.call_count, 0, "Did not expect any ERRORS; Got: {0}".format(mock_logger.error.call_args))

    def test_run_command_it_should_not_log_by_default(self):
        self.__it_should_not_log_by_default(
            lambda: shellutil.run_command(["ls", "nonexistent_file"]))  # Raises a CommandError

        self.__it_should_not_log_by_default(
            lambda: shellutil.run_command("nonexistent_command"))  # Raises an OSError

    def test_run_pipe_it_should_not_log_by_default(self):
        self.__it_should_not_log_by_default(
            lambda: shellutil.run_pipe([["date"], [self.__create_tee_script(return_code=1)]]))  # Raises a CommandError

        self.__it_should_not_log_by_default(
            lambda: shellutil.run_pipe([["date"], ["nonexistent_command"]]))  # Raises an OSError

    def __it_should_log_an_error_when_log_error_is_set(self, action, command):
        with patch("azurelinuxagent.common.utils.shellutil.logger.error") as mock_log_error:
            try:
                action()
            except Exception:
                pass

            self.assertEqual(mock_log_error.call_count, 1)

            args, _ = mock_log_error.call_args
            self.assertTrue(any(command in str(a) for a in args), "The command was not logged")
            self.assertTrue(any("2" in str(a) for a in args), "The command's return code was not logged")  # errno 2: No such file or directory

    def test_run_command_should_log_an_error_when_log_error_is_set(self):
        self.__it_should_log_an_error_when_log_error_is_set(
            lambda: shellutil.run_command(["ls", "file-does-not-exist"], log_error=True),  # Raises a CommandError
            command="ls")

        self.__it_should_log_an_error_when_log_error_is_set(
            lambda: shellutil.run_command("command-does-not-exist", log_error=True),  # Raises a CommandError
            command="command-does-not-exist")

    def test_run_command_should_raise_when_both_the_input_and_stdin_parameters_are_specified(self):
        with tempfile.TemporaryFile() as input_file:
            with self.assertRaises(ValueError):
                shellutil.run_command(["cat"], input='0123456789ABCDEF', stdin=input_file)

    def test_run_command_should_read_the_command_input_from_the_input_parameter_when_it_is_a_string(self):
        command_input = 'TEST STRING'
        output = shellutil.run_command(["cat"], input=command_input)
        self.assertEqual(output, command_input, "The command did not process its input correctly; the output should match the input")

    def test_run_command_should_read_stdin_from_the_input_parameter_when_it_is_a_sequence_of_bytes(self):
        command_input = 'TEST BYTES'
        output = shellutil.run_command(["cat"], input=command_input)
        self.assertEqual(output, command_input, "The command did not process its input correctly; the output should match the input")

    def __it_should_read_the_command_input_from_the_stdin_parameter(self, action):
        command_input = 'TEST STRING\n'
        with tempfile.TemporaryFile() as input_file:
            input_file.write(command_input.encode())
            input_file.seek(0)

            output = action(stdin=input_file)

            self.assertEqual(output, command_input, "The command did not process its input correctly; the output should match the input")

    def test_run_command_should_read_the_command_input_from_the_stdin_parameter(self):
        self.__it_should_read_the_command_input_from_the_stdin_parameter(
            lambda stdin: shellutil.run_command(["cat"], stdin=stdin))

    def test_run_pipe_should_read_the_command_input_from_the_stdin_parameter(self):
        self.__it_should_read_the_command_input_from_the_stdin_parameter(
            lambda stdin: shellutil.run_pipe([["cat"], ["sort"]], stdin=stdin))

    def __it_should_write_the_command_output_to_the_stdout_parameter(self, action):
        with tempfile.TemporaryFile() as output_file:
            captured_output = action(stdout=output_file)

            output_file.seek(0)
            command_output = ustr(output_file.read(), encoding='utf-8', errors='backslashreplace')

            self.assertEqual(command_output, "TEST STRING\n", "The command did not produce the correct output; the output should match the input")
            self.assertEqual("", captured_output, "No output should have been captured since it was redirected to a file. Output: [{0}]".format(captured_output))

    def test_run_command_should_write_the_command_output_to_the_stdout_parameter(self):
        self.__it_should_write_the_command_output_to_the_stdout_parameter(
            lambda stdout: shellutil.run_command(["echo", "TEST STRING"], stdout=stdout))

    def test_run_pipe_should_write_the_command_output_to_the_stdout_parameter(self):
        self.__it_should_write_the_command_output_to_the_stdout_parameter(
            lambda stdout: shellutil.run_pipe([["echo", "TEST STRING"], ["sort"]], stdout=stdout))

    def __it_should_write_the_command_error_output_to_the_stderr_parameter(self, action):
        with tempfile.TemporaryFile() as output_file:
            action(stderr=output_file)

            output_file.seek(0)
            command_error_output = ustr(output_file.read(), encoding='utf-8', errors="backslashreplace")

            self.assertEqual("TEST STRING\n", command_error_output, "stderr was not redirected to the output file correctly")

    def test_run_command_should_write_the_command_error_output_to_the_stderr_parameter(self):
        self.__it_should_write_the_command_error_output_to_the_stderr_parameter(
            lambda stderr: shellutil.run_command(self.__create_tee_script(), input="TEST STRING\n", stderr=stderr))

    def test_run_pipe_should_write_the_command_error_output_to_the_stderr_parameter(self):
        self.__it_should_write_the_command_error_output_to_the_stderr_parameter(
            lambda stderr: shellutil.run_pipe([["echo", "TEST STRING"], [self.__create_tee_script()]], stderr=stderr))

    def test_run_pipe_should_capture_the_stderr_of_all_the_commands_in_the_pipe(self):
        with self.assertRaises(shellutil.CommandError) as context_manager:
            shellutil.run_pipe([
                ["echo", "TEST STRING"],
                [self.__create_tee_script()],
                [self.__create_tee_script()],
                [self.__create_tee_script(return_code=1)]])

        self.assertEqual("TEST STRING\n" * 3, context_manager.exception.stderr, "Expected 3 copies of the test string since there are 3 commands in the pipe")

    def test_run_command_should_return_a_string_by_default(self):
        output = shellutil.run_command(self.__create_tee_script(), input="TEST STRING")

        self.assertTrue(isinstance(output, ustr), "The return value should be a string. Got: '{0}'".format(type(output)))

    def test_run_pipe_should_return_a_string_by_default(self):
        output = shellutil.run_pipe([["echo", "TEST STRING"], [self.__create_tee_script()]])

        self.assertTrue(isinstance(output, ustr), "The return value should be a string. Got: '{0}'".format(type(output)))

    def test_run_command_should_return_a_bytes_object_when_encode_output_is_false(self):
        output = shellutil.run_command(self.__create_tee_script(), input="TEST STRING", encode_output=False)

        self.assertTrue(isinstance(output, bytes), "The return value should be a bytes object. Got: '{0}'".format(type(output)))

    def test_run_pipe_should_return_a_bytes_object_when_encode_output_is_false(self):
        output = shellutil.run_pipe([["echo", "TEST STRING"], [self.__create_tee_script()]], encode_output=False)

        self.assertTrue(isinstance(output, bytes), "The return value should be a bytes object. Got: '{0}'".format(type(output)))

    # R0912: Too many branches (13/12) (too-many-branches) -- Disabled: Branches are sequential
    def test_run_command_run_pipe_run_get_output_should_notify_when_commands_start_and_complete(self):  # pylint:disable=R0912
        # The children processes run this script, which creates a file (this signals that process has started) and then sleeps for a long time
        child_script = os.path.join(self.tmp_dir, "should_notify_when_commands_start_and_complete.py")
        AgentTestCase.create_script(child_script, """
import os
import sys
import time

with open(sys.argv[1], "w") as signal_file:
    signal_file.write("{0} {1}".format(os.getpid(), os.getppid()))
time.sleep(60)
""")

        threads = []

        try:
            child_processes = []
            parent_processes = []

            started_commands = []
            completed_commands = []

            # W0108: Lambda may not be necessary (unnecessary-lambda) - The use of lambda is appropriate
            shellutil.set_on_command_started_callback(lambda pid: started_commands.append(pid))  # pylint:disable=W0108
            shellutil.set_on_command_completed_callback(lambda pid: completed_commands.append(pid))  # pylint:disable=W0108

            try:
                # we use these files to signal that the commands are running
                signal_files = [os.path.join(self.tmp_dir, "should_notify_when_commands_start_and_complete.txt.{0}".format(i)) for i in range(4)]

                # we test these commands
                commands_to_execute = [
                    # run_get_output must be the first in this list; see the code to fetch the PIDs a few lines below
                    lambda: shellutil.run_get_output("{0} {1}".format(child_script, signal_files[0])),
                    lambda: shellutil.run_command([child_script, signal_files[1]]),
                    lambda: shellutil.run_pipe([[child_script, signal_files[2]], [child_script, signal_files[3]]]),
                ]

                # start each command on a separate thread (since we need to examine them while they are running)
                def invoke(command):
                    try:
                        command()
                    except shellutil.CommandError as command_error:
                        if command_error.returncode != -9:  # test cleanup terminates the commands, so this is expected
                            raise

                for cmd in commands_to_execute:
                    thread = threading.Thread(target=invoke, args=(cmd,))
                    thread.start()
                    threads.append(thread)

                # wait for all the commands to create their signal files (this indicates the child processes are running and are alive)
                all_children_started = False
                start_time = datetime.datetime.now()
                while not all_children_started and self._to_seconds(datetime.datetime.now() - start_time) < 30:
                    all_children_started = all(os.path.exists(file) for file in signal_files)
                    time.sleep(0.01)
                if not all_children_started:
                    raise Exception("The child processes did not start within the allowed timeout")

                # now fetch the PIDs in the signal files
                for sig_file in signal_files:
                    with open(sig_file, "r") as read_handle:
                        pids = read_handle.read().split()
                        child_processes.append(int(pids[0]))
                        parent_processes.append(int(pids[1]))

                # the first item to in the PIDs we fetched corresponds run_get_output, which invokes the command using the
                # shell, so in that case we need to use the parent's pid (which was the process we started)
                started_commands_expected = parent_processes[0:1] + child_processes[1:]

                #
                # Check the command_started callback
                #
                started_commands.sort()
                started_commands_expected.sort()
                self.assertEqual(
                    started_commands_expected,
                    started_commands,
                    "The command_started callback was not invoked with the correct processes. Got: {0}".format(
                        [self._get_command_line(pid) for pid in started_commands_expected]))

            finally:
                # terminate the child processes, since they are blocked
                for pid in child_processes:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except Exception:
                        pass  # no need to handle this error

            #
            # Check the command_completed callback, but we need to wait for the callbacks first
            #
            start_time = datetime.datetime.now()
            while len(completed_commands) != len(started_commands) and self._to_seconds (datetime.datetime.now() - start_time) < 10:
                time.sleep(0.01)
            if len(completed_commands) != len(started_commands):
                raise Exception("The child processes did not complete within the allowed timeout")

            completed_commands.sort()
            self.assertEqual(
                started_commands,
                completed_commands,
                "The command_completed callback does not match the invocations of command_started. Got: {0}".format(
                    [self._get_command_line(pid) for pid in started_commands]))
        finally:
            shellutil.set_on_command_started_callback(None)
            shellutil.set_on_command_completed_callback(None)

            for thread in threads:
                thread.join(timeout=5)

    @staticmethod
    def _get_command_line(pid):
        try:
            cmdline = '/proc/{0}/cmdline'.format(pid)
            if os.path.exists(cmdline):
                with open(cmdline, "r") as cmdline_file:
                    return cmdline_file.read()
        except Exception:
            pass
        return "UNKNOWN [PID: {0}]".format(pid)

    @staticmethod
    def _to_seconds(time_delta):
        return (time_delta.microseconds + (time_delta.seconds + time_delta.days * 24 * 3600) * 10**6) / 10**6


if __name__ == '__main__':
    unittest.main()
