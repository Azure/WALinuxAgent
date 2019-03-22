# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json
import re
import stat

from azurelinuxagent.common.protocol.restapi import ExtensionStatus, Extension, ExtHandler, ExtHandlerProperties
from azurelinuxagent.ga.exthandlers import parse_ext_status, ExtHandlerInstance, get_exthandlers_handler
from azurelinuxagent.common.exception import ProtocolError, ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.utils.processutil import TELEMETRY_MESSAGE_MAX_LEN, format_stdout_stderr
from azurelinuxagent.common.cgroups import CGroups
from tests.tools import *


class TestExtHandlers(AgentTestCase):
    def test_parse_extension_status00(self):
        """
        Parse a status report for a successful execution of an extension.
        """

        s = '''[{
    "status": {
      "status": "success",
      "formattedMessage": {
        "lang": "en-US",
        "message": "Command is finished."
      },
      "operation": "Daemon",
      "code": "0",
      "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"
    },
    "version": "1.0",
    "timestampUTC": "2018-04-20T21:20:24Z"
  }
]'''
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, json.loads(s))

        self.assertEqual('0', ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual('Command is finished.', ext_status.message)
        self.assertEqual('Daemon', ext_status.operation)
        self.assertEqual('success', ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

    def test_parse_extension_status01(self):
        """
        Parse a status report for a failed execution of an extension.

        The extension returned a bad status/status of failed.
        The agent should handle this gracefully, and convert all unknown
        status/status values into an error.
        """

        s = '''[{
    "status": {
      "status": "failed",
      "formattedMessage": {
        "lang": "en-US",
        "message": "Enable failed: Failed with error: commandToExecute is empty or invalid ..."
      },
      "operation": "Enable",
      "code": "0",
      "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"
    },
    "version": "1.0",
    "timestampUTC": "2018-04-20T20:50:22Z"
}]'''
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, json.loads(s))

        self.assertEqual('0', ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual('Enable failed: Failed with error: commandToExecute is empty or invalid ...', ext_status.message)
        self.assertEqual('Enable', ext_status.operation)
        self.assertEqual('error', ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

    def test_parse_ext_status_should_parse_missing_substatus_as_empty(self):
        status = '''[{
            "status": {
              "status": "success",
              "formattedMessage": {
                "lang": "en-US",
                "message": "Command is finished."
              },
              "operation": "Enable",
              "code": "0",
              "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"
            },
            
            "version": "1.0",
            "timestampUTC": "2018-04-20T21:20:24Z"
          }
        ]'''

        extension_status = ExtensionStatus(seq_no=0)

        parse_ext_status(extension_status, json.loads(status))

        self.assertTrue(isinstance(extension_status.substatusList, list), 'substatus was not parsed correctly')
        self.assertEqual(0, len(extension_status.substatusList))

    def test_parse_ext_status_should_parse_null_substatus_as_empty(self):
        status = '''[{
            "status": {
              "status": "success",
              "formattedMessage": {
                "lang": "en-US",
                "message": "Command is finished."
              },
              "operation": "Enable",
              "code": "0",
              "name": "Microsoft.OSTCExtensions.CustomScriptForLinux",
              "substatus": null
            },

            "version": "1.0",
            "timestampUTC": "2018-04-20T21:20:24Z"
          }
        ]'''

        extension_status = ExtensionStatus(seq_no=0)

        parse_ext_status(extension_status, json.loads(status))

        self.assertTrue(isinstance(extension_status.substatusList, list), 'substatus was not parsed correctly')
        self.assertEqual(0, len(extension_status.substatusList))

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_largest_seq_no')
    def assert_extension_sequence_number(self,
                                         patch_get_largest_seq,
                                         patch_add_event,
                                         goal_state_sequence_number,
                                         disk_sequence_number,
                                         expected_sequence_number):
        ext = Extension()
        ext.sequenceNumber = goal_state_sequence_number
        patch_get_largest_seq.return_value = disk_sequence_number

        ext_handler_props = ExtHandlerProperties()
        ext_handler_props.version = "1.2.3"
        ext_handler = ExtHandler(name='foo')
        ext_handler.properties = ext_handler_props

        instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)
        seq, path = instance.get_status_file_path(ext)

        try:
            gs_seq_int = int(goal_state_sequence_number)
            gs_int = True
        except ValueError:
            gs_int = False

        if gs_int and gs_seq_int != disk_sequence_number:
            self.assertEqual(1, patch_add_event.call_count)
            args, kw_args = patch_add_event.call_args
            self.assertEqual('SequenceNumberMismatch', kw_args['op'])
            self.assertEqual(False, kw_args['is_success'])
            self.assertEqual('Goal state: {0}, disk: {1}'
                             .format(gs_seq_int, disk_sequence_number),
                             kw_args['message'])
        else:
            self.assertEqual(0, patch_add_event.call_count)

        self.assertEqual(expected_sequence_number, seq)
        if seq > -1:
            self.assertTrue(path.endswith('/foo-1.2.3/status/{0}.status'.format(expected_sequence_number)))
        else:
            self.assertIsNone(path)

    def test_extension_sequence_number(self):
        self.assert_extension_sequence_number(goal_state_sequence_number="12",
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" 12 ",
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" foo",
                                              disk_sequence_number=3,
                                              expected_sequence_number=3)

        self.assert_extension_sequence_number(goal_state_sequence_number="-1",
                                              disk_sequence_number=3,
                                              expected_sequence_number=-1)

    @patch("azurelinuxagent.ga.exthandlers.add_event")
    @patch("azurelinuxagent.common.errorstate.ErrorState.is_triggered")
    @patch("azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol")
    def test_it_should_report_an_error_if_the_wireserver_cannot_be_reached(self, patch_get_protocol, patch_is_triggered, patch_add_event):
        test_message = "TEST MESSAGE"

        patch_get_protocol.side_effect = ProtocolError(test_message) # get_protocol will throw if the wire server cannot be reached
        patch_is_triggered.return_value = True # protocol errors are reported only after a delay; force the error to be reported now

        get_exthandlers_handler().run()

        self.assertEquals(patch_add_event.call_count, 2)

        _, first_call_args = patch_add_event.call_args_list[0]
        self.assertEquals(first_call_args['op'], WALAEventOperation.GetArtifactExtended)
        self.assertEquals(first_call_args['is_success'], False)

        _, second_call_args = patch_add_event.call_args_list[1]
        self.assertEquals(second_call_args['op'], WALAEventOperation.ExtensionProcessing)
        self.assertEquals(second_call_args['is_success'], False)
        self.assertIn(test_message, second_call_args['message'])


class LaunchCommandTestCase(AgentTestCase):
    """
    Test cases for launch_command
    """

    def setUp(self):
        AgentTestCase.setUp(self)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = "1.2.3"
        self.ext_handler = ExtHandler(name='foo')
        self.ext_handler.properties = ext_handler_properties
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=self.ext_handler, protocol=None)

        self.base_cgroups = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.base_cgroups)
        os.mkdir(os.path.join(self.base_cgroups, "cpu"))
        os.mkdir(os.path.join(self.base_cgroups, "memory"))

        self.mock__base_cgroups = patch("azurelinuxagent.common.cgroups.BASE_CGROUPS", self.base_cgroups)
        self.mock__base_cgroups.start()

        self.mock_get_base_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir)
        self.mock_get_base_dir.start()

        log_dir = os.path.join(self.tmp_dir, "log")
        self.mock_get_log_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir)
        self.mock_get_log_dir.start()

    def tearDown(self):
        self.mock_get_log_dir.stop()
        self.mock_get_base_dir.stop()
        self.mock__base_cgroups.stop()

        AgentTestCase.tearDown(self)

    def _create_script(self, file_name, contents):
        """
        Creates an executable script with the given contents.
        If file_name ends with ".py", it creates a Python3 script, otherwise it creates a bash script
        """
        file_path = os.path.join(self.ext_handler_instance.get_base_dir(), file_name)

        with open(file_path, "w") as script:
            if file_name.endswith(".py"):
                script.write("#!/usr/bin/env python3\n")
            else:
                script.write("#!/usr/bin/env bash\n")
            script.write(contents)

        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        return file_name

    @staticmethod
    def _output_regex(stdout, stderr):
        return r"\[stdout\]\s+{0}\s+\[stderr\]\s+{1}".format(stdout, stderr)

    @staticmethod
    def _find_process(command):
        for pid in [pid for pid in os.listdir('/proc') if pid.isdigit()]:
            try:
                with open(os.path.join('/proc', pid, 'cmdline'), 'r') as cmdline:
                    for line in cmdline.readlines():
                        if command in line:
                            return True
            except IOError:  # proc has already terminated
                continue
        return False

    def test_it_should_capture_the_output_of_the_command(self):
        stdout = "stdout" * 5
        stderr = "stderr" * 5

        command = self._create_script("produce_output.py", '''
import sys

sys.stdout.write("{0}")
sys.stderr.write("{1}")

'''.format(stdout, stderr))

        def list_directory():
            base_dir = self.ext_handler_instance.get_base_dir()
            return [i for i in os.listdir(base_dir) if not i.endswith(".tld")] # ignore telemetry files

        files_before = list_directory()

        output = self.ext_handler_instance.launch_command(command)

        files_after = list_directory()

        self.assertRegex(output, LaunchCommandTestCase._output_regex(stdout, stderr))

        self.assertListEqual(files_before, files_after, "Not all temporary files were deleted. File list: {0}".format(files_after))

    def test_it_should_raise_an_exception_when_the_command_times_out(self):
        extension_error_code = ExtensionErrorCodes.PluginHandlerScriptTimedout
        stdout = "stdout" * 7
        stderr = "stderr" * 7

        # the signal file is used by the test command to indicate it has produced output
        signal_file = os.path.join(self.tmp_dir, "signal_file.txt")

        # the test command produces some output then goes into an infinite loop
        command = self._create_script("produce_output_then_hang.py", '''
import sys
import time

sys.stdout.write("{0}")
sys.stdout.flush()

sys.stderr.write("{1}")
sys.stderr.flush()

with open("{2}", "w") as file:
    while True:
        file.write(".")
        time.sleep(1)

'''.format(stdout, stderr, signal_file))

        # mock time.sleep to wait for the signal file (launch_command implements the time out using polling and sleep)
        original_sleep = time.sleep

        def sleep(seconds):
            if not os.path.exists(signal_file):
                original_sleep(seconds)

        timeout = 60

        start_time = time.time()

        with patch("time.sleep", side_effect=sleep, autospec=True) as mock_sleep:

            with self.assertRaises(ExtensionError) as context_manager:
                self.ext_handler_instance.launch_command(command, timeout=timeout, extension_error_code=extension_error_code)

            # the command name and its output should be part of the message
            message = str(context_manager.exception)
            self.assertRegex(message, r"Timeout\(\d+\):\s+{0}\s+{1}".format(command, LaunchCommandTestCase._output_regex(stdout, stderr)))

            # the exception code should be as specified in the call to launch_command
            self.assertEquals(context_manager.exception.code, extension_error_code)

            # the timeout period should have elapsed
            self.assertGreaterEqual(mock_sleep.call_count, timeout)

            # the command should have been terminated
            self.assertFalse(LaunchCommandTestCase._find_process(command), "The command was not terminated")

        # as a check for the test itself, verify it completed in just a few seconds
        self.assertLessEqual(time.time() - start_time, 5)

    def test_it_should_raise_an_exception_when_the_command_fails(self):
        extension_error_code = 2345
        stdout = "stdout" * 3
        stderr = "stderr" * 3
        exit_code = 99

        command = self._create_script("fail.py", '''
import sys

sys.stdout.write("{0}")
sys.stderr.write("{1}")
exit({2})

'''.format(stdout, stderr, exit_code))

        # the output is captured as part of the exception message
        with self.assertRaises(ExtensionError) as context_manager:
            self.ext_handler_instance.launch_command(command, extension_error_code=extension_error_code)

        message = str(context_manager.exception)
        self.assertRegex(message, r"Non-zero exit code: {0}.+{1}\s+{2}".format(exit_code, command, LaunchCommandTestCase._output_regex(stdout, stderr)))

        self.assertEquals(context_manager.exception.code, extension_error_code)

    def test_it_should_not_wait_for_child_process(self):
        stdout = "stdout"
        stderr = "stderr"

        command = self._create_script("start_child_process.py", '''
import os
import sys
import time

pid = os.fork()

if pid == 0:
    time.sleep(60)
else:
    sys.stdout.write("{0}")
    sys.stderr.write("{1}")
    
'''.format(stdout, stderr))

        start_time = time.time()

        output = self.ext_handler_instance.launch_command(command)

        self.assertLessEqual(time.time() - start_time, 5)

        # Also check that we capture the parent's output
        self.assertRegex(output, LaunchCommandTestCase._output_regex(stdout, stderr))

    def test_it_should_capture_the_output_of_child_process(self):
        parent_stdout = "PARENT STDOUT"
        parent_stderr = "PARENT STDERR"
        child_stdout = "CHILD STDOUT"
        child_stderr = "CHILD STDERR"
        more_parent_stdout = "MORE PARENT STDOUT"
        more_parent_stderr = "MORE PARENT STDERR"

        # the child process uses the signal file to indicate it has produced output
        signal_file = os.path.join(self.tmp_dir, "signal_file.txt")

        command = self._create_script("start_child_with_output.py", '''
import os
import sys
import time

sys.stdout.write("{0}")
sys.stderr.write("{1}")

pid = os.fork()

if pid == 0:
    sys.stdout.write("{2}")
    sys.stderr.write("{3}")
    
    open("{6}", "w").close()
else:
    sys.stdout.write("{4}")
    sys.stderr.write("{5}")
    
    while not os.path.exists("{6}"):
        time.sleep(0.5)
    
'''.format(parent_stdout, parent_stderr, child_stdout, child_stderr, more_parent_stdout, more_parent_stderr, signal_file))

        output = self.ext_handler_instance.launch_command(command)

        self.assertIn(parent_stdout, output)
        self.assertIn(parent_stderr, output)

        self.assertIn(child_stdout, output)
        self.assertIn(child_stderr, output)

        self.assertIn(more_parent_stdout, output)
        self.assertIn(more_parent_stderr, output)

    def test_it_should_capture_the_output_of_child_process_that_fails_to_start(self):
        parent_stdout = "PARENT STDOUT"
        parent_stderr = "PARENT STDERR"
        child_stdout = "CHILD STDOUT"
        child_stderr = "CHILD STDERR"

        command = self._create_script("start_child_that_fails.py", '''
import os
import sys
import time

pid = os.fork()

if pid == 0:
    sys.stdout.write("{0}")
    sys.stderr.write("{1}")
    exit(1)
else:
    sys.stdout.write("{2}")
    sys.stderr.write("{3}")

'''.format(child_stdout, child_stderr, parent_stdout, parent_stderr))

        output = self.ext_handler_instance.launch_command(command)

        self.assertIn(parent_stdout, output)
        self.assertIn(parent_stderr, output)

        self.assertIn(child_stdout, output)
        self.assertIn(child_stderr, output)

    def test_it_should_execute_commands_with_no_output(self):
        # file used to verify the command completed successfully
        signal_file = os.path.join(self.tmp_dir, "signal_file.txt")

        command = self._create_script("create_file.py", '''
open("{0}", "w").close()

'''.format(signal_file))

        output = self.ext_handler_instance.launch_command(command)

        self.assertTrue(os.path.exists(signal_file))
        self.assertRegex(output, LaunchCommandTestCase._output_regex('', ''))

    def test_it_should_not_capture_the_output_of_commands_that_do_their_own_redirection(self):
        # the test script redirects its output to this file
        command_output_file = os.path.join(self.tmp_dir, "command_output.txt")
        stdout = "STDOUT"
        stderr = "STDERR"

        # the test script mimics the redirection done by the Custom Script extension
        command = self._create_script("produce_output", '''
exec &> {0}
echo {1}
>&2 echo {2}

'''.format(command_output_file, stdout, stderr))

        output = self.ext_handler_instance.launch_command(command)

        self.assertRegex(output, LaunchCommandTestCase._output_regex('', ''))

        with open(command_output_file, "r") as command_output:
            output = command_output.read()
            self.assertEquals(output, "{0}\n{1}\n".format(stdout, stderr))

    def test_it_should_truncate_the_command_output(self):
        stdout = "STDOUT"
        stderr = "STDERR"

        command = self._create_script("produce_long_output.py", '''
import sys

sys.stdout.write( "{0}" * {1})
sys.stderr.write( "{2}" * {3})
'''.format(stdout, int(TELEMETRY_MESSAGE_MAX_LEN / len(stdout)), stderr, int(TELEMETRY_MESSAGE_MAX_LEN / len(stderr))))

        output = self.ext_handler_instance.launch_command(command)

        self.assertLessEqual(len(output), TELEMETRY_MESSAGE_MAX_LEN)
        self.assertIn(stdout, output)
        self.assertIn(stderr, output)

    def test_it_should_read_only_the_head_of_large_outputs(self):
        command = self._create_script("produce_long_output.py", '''
import sys

sys.stdout.write("O" * 5 * 1024 * 1024)
sys.stderr.write("E" * 5 * 1024 * 1024)
''')

        # Mocking the call to file.read() is difficult, so instead we mock the call to format_stdout_stderr, which takes the
        # return value of the calls to file.read(). The intention of the test is to verify we never read (and load in memory)
        # more than a few KB of data from the files used to capture stdout/stderr
        with patch('azurelinuxagent.ga.exthandlers.format_stdout_stderr', side_effect=format_stdout_stderr) as mock_format:
            output = self.ext_handler_instance.launch_command(command)

        self.assertGreaterEqual(len(output), 1024)
        self.assertLessEqual(len(output), TELEMETRY_MESSAGE_MAX_LEN)

        mock_format.assert_called_once()

        args, kwargs = mock_format.call_args
        stdout, stderr = args

        self.assertGreaterEqual(len(stdout), 1024)
        self.assertLessEqual(len(stdout), TELEMETRY_MESSAGE_MAX_LEN)

        self.assertGreaterEqual(len(stderr), 1024)
        self.assertLessEqual(len(stderr), TELEMETRY_MESSAGE_MAX_LEN)

    def test_it_should_handle_errors_while_reading_the_command_output(self):
        command = self._create_script("produce_output.py", '''
import sys

sys.stdout.write("STDOUT")
sys.stderr.write("STDERR")
''')

        # Mocking the call to file.read() is difficult, so instead we mock the call to _capture_process_output, which will
        # call file.read() and we force stdout/stderr to be None; this will produce an exception when trying to use these files.
        original_capture_process_output = ExtHandlerInstance._capture_process_output

        def capture_process_output(process, stdout_file, stderr_file, cmd, timeout, code):
            return original_capture_process_output(process, None, None, cmd, timeout, code)

        with patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance._capture_process_output', side_effect=capture_process_output):
            output = self.ext_handler_instance.launch_command(command)

        self.assertIn("[stderr]\nCannot read stdout/stderr:", output)

    def test_it_should_handle_exceptions_from_cgroups_and_run_command(self):
        # file used to verify the command completed successfully
        signal_file = os.path.join(self.tmp_dir, "signal_file.txt")

        command = self._create_script("create_file.py", '''
open("{0}", "w").close()

'''.format(signal_file))

        with patch('azurelinuxagent.common.cgroups.CGroups.for_extension', side_effect=Exception):
            self.ext_handler_instance.launch_command(command)

        self.assertTrue(os.path.exists(signal_file))

    @skip_if_predicate_false(CGroups.enabled, "CGroups not supported in this environment")
    def test_it_should_add_the_child_process_to_its_own_cgroup(self):
        # We are checking for the parent PID here since the PID getting written to the corresponding cgroup
        # would be from the shell process started before launch_command invokes the actual command.
        # In a non-mocked scenario, the kernel would actually also write all the children's PIDs to the procs
        # file as well, but here we are mocking the base cgroup path, so it is not taken care for us.
        command = self._create_script("output_parent_pid.py", '''
import os

print(os.getppid())

''')

        output = self.ext_handler_instance.launch_command(command)

        match = re.match(LaunchCommandTestCase._output_regex('(\d+)', '.*'), output)
        if match is None or match.group(1) is None:
            raise Exception("Could not extract the PID of the child command from its output")

        expected_pid = int(match.group(1))

        controllers = os.listdir(self.base_cgroups)
        for c in controllers:
            procs = os.path.join(self.base_cgroups, c, "WALinuxAgent", self.ext_handler.name, "cgroup.procs")
            with open(procs, "r") as f:
                contents = f.read()
                pid = int(contents)

                self.assertNotEqual(os.getpid(), pid, "The PID {0} added to {1} was of the launch command caller, not the command itself.".format(pid, procs))
                self.assertEquals(pid, expected_pid, "The PID of the command was not added to {0}. Expected: {1}, got: {2}".format(procs, expected_pid, pid))

