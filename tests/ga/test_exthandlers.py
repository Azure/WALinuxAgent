# Copyright 2020 Microsoft Corporation
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

import json
import os
import subprocess
import time
import uuid

from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.event import AGENT_EVENT_FILE_EXTENSION, WALAEventOperation
from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.protocol.restapi import ExtensionStatus, Extension, ExtHandler, ExtHandlerProperties
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils.extensionprocessutil import TELEMETRY_MESSAGE_MAX_LEN, format_stdout_stderr, \
    read_output
from azurelinuxagent.ga.exthandlers import parse_ext_status, ExtHandlerInstance, ExtCommandEnvVariable, \
    ExtensionStatusError
from tests.protocol import mockwiredata
from tests.protocol.mocks import mock_wire_protocol
from tests.tools import AgentTestCase, patch, mock_sleep, clear_singleton_instances


class TestExtHandlers(AgentTestCase):

    def setUp(self):
        super(TestExtHandlers, self).setUp()
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def test_parse_ext_status_should_raise_on_non_array(self):
        status = json.loads('''
            {{
                "status": {{
                    "status": "transitioning",
                    "operation": "Enabling Handler",
                    "code": 0,
                    "name": "Microsoft.Azure.RecoveryServices.SiteRecovery.Linux"
                }},
                "version": 1.0,
                "timestampUTC": "2020-01-14T15:04:43Z",
                "longText": "{0}"
            }}'''.format("*" * 5 * 1024))

        with self.assertRaises(ExtensionStatusError) as context_manager:
            parse_ext_status(ExtensionStatus(seq_no=0), status)
        error_message = str(context_manager.exception)
        self.assertIn("The extension status must be an array", error_message)
        self.assertTrue(0 < len(error_message) - 64 < 4096, "The error message should not be much longer than 4K characters: [{0}]".format(error_message))

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

    def test_parse_extension_status_with_empty_status(self):
        """
        Parse a status report for a successful execution of an extension.
        """

        # Validating empty status case
        s = '''[]'''
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, json.loads(s))

        self.assertEqual(None, ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual(None, ext_status.message)
        self.assertEqual(None, ext_status.operation)
        self.assertEqual(None, ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

        # Validating None case
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, None)

        self.assertEqual(None, ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual(None, ext_status.message)
        self.assertEqual(None, ext_status.operation)
        self.assertEqual(None, ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance._get_last_modified_seq_no_from_config_files')
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
            args, kw_args = patch_add_event.call_args  # pylint: disable=unused-variable
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
        self.assert_extension_sequence_number(goal_state_sequence_number="12",  # pylint: disable=no-value-for-parameter
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" 12 ",  # pylint: disable=no-value-for-parameter
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" foo",  # pylint: disable=no-value-for-parameter
                                              disk_sequence_number=3,
                                              expected_sequence_number=3)

        self.assert_extension_sequence_number(goal_state_sequence_number="-1",  # pylint: disable=no-value-for-parameter
                                              disk_sequence_number=3,
                                              expected_sequence_number=-1)

    def test_it_should_report_error_if_plugin_settings_version_mismatch(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_PLUGIN_SETTINGS_MISMATCH) as protocol:
            with patch("azurelinuxagent.common.protocol.goal_state.add_event") as mock_add_event:
                # Forcing update of GoalState to allow the ExtConfig to report an event
                protocol.mock_wire_data.set_incarnation(2)
                protocol.client.update_goal_state()
                plugin_setting_mismatch_calls = [kw for _, kw in mock_add_event.call_args_list if
                                                 kw['op'] == WALAEventOperation.PluginSettingsVersionMismatch]
                self.assertEqual(1, len(plugin_setting_mismatch_calls),
                                 "PluginSettingsMismatch event should be reported once")
                self.assertIn('ExtHandler PluginSettings Version Mismatch! Expected PluginSettings version: 1.0.0 for Handler: OSTCExtensions.ExampleHandlerLinux'
                              , plugin_setting_mismatch_calls[0]['message'],
                    "Invalid error message with incomplete data detected for PluginSettingsVersionMismatch")
                self.assertTrue("1.0.2" in plugin_setting_mismatch_calls[0]['message'] and "1.0.1" in plugin_setting_mismatch_calls[0]['message'],
                              "Error message should contain the incorrect versions")
                self.assertFalse(plugin_setting_mismatch_calls[0]['is_success'], "The event should be false")

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
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=self.ext_handler, protocol=WireProtocol("1.2.3.4"))

        self.mock_get_base_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir)
        self.mock_get_base_dir.start()

        self.log_dir = os.path.join(self.tmp_dir, "log")
        self.mock_get_log_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir)
        self.mock_get_log_dir.start()

        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.01))
        self.mock_sleep.start()

        self.cgroups_enabled = CGroupConfigurator.get_instance().enabled()
        CGroupConfigurator.get_instance().disable()

    def tearDown(self):
        if self.cgroups_enabled:
            CGroupConfigurator.get_instance().enable()
        else:
            CGroupConfigurator.get_instance().disable()

        self.mock_get_log_dir.stop()
        self.mock_get_base_dir.stop()
        self.mock_sleep.stop()

        AgentTestCase.tearDown(self)

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

        command = "produce_output.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
import sys

sys.stdout.write("{0}")
sys.stderr.write("{1}")

'''.format(stdout, stderr))

        def list_directory():
            base_dir = self.ext_handler_instance.get_base_dir()
            return [i for i in os.listdir(base_dir) if not i.endswith(AGENT_EVENT_FILE_EXTENSION)] # ignore telemetry files

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
        command = "produce_output_then_hang.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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
        def sleep(seconds):
            if not os.path.exists(signal_file):
                sleep.original_sleep(seconds)
        sleep.original_sleep = time.sleep

        timeout = 60

        start_time = time.time()

        with patch("time.sleep", side_effect=sleep, autospec=True) as mock_sleep:  # pylint: disable=redefined-outer-name

            with self.assertRaises(ExtensionError) as context_manager:
                self.ext_handler_instance.launch_command(command, timeout=timeout, extension_error_code=extension_error_code)

            # the command name and its output should be part of the message
            message = str(context_manager.exception)
            command_full_path = os.path.join(self.tmp_dir, command.lstrip(os.path.sep))
            self.assertRegex(message, r"Timeout\(\d+\):\s+{0}\s+{1}".format(command_full_path, LaunchCommandTestCase._output_regex(stdout, stderr)))

            # the exception code should be as specified in the call to launch_command
            self.assertEqual(context_manager.exception.code, extension_error_code)

            # the timeout period should have elapsed
            self.assertGreaterEqual(mock_sleep.call_count, timeout)

            # The command should have been terminated.
            # The /proc file system may still include the process when we do this check so we try a few times after a short delay; note that we
            # are mocking sleep, so we need to use the original implementation.
            terminated = False
            i = 0
            while not terminated and i < 4:
                if not LaunchCommandTestCase._find_process(command):
                    terminated = True
                else:
                    sleep.original_sleep(0.25)
                i += 1

            self.assertTrue(terminated, "The command was not terminated")

        # as a check for the test itself, verify it completed in just a few seconds
        self.assertLessEqual(time.time() - start_time, 5)

    def test_it_should_raise_an_exception_when_the_command_fails(self):
        extension_error_code = 2345
        stdout = "stdout" * 3
        stderr = "stderr" * 3
        exit_code = 99

        command = "fail.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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

        self.assertEqual(context_manager.exception.code, extension_error_code)

    def test_it_should_not_wait_for_child_process(self):
        stdout = "stdout"
        stderr = "stderr"

        command = "start_child_process.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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

        command = "start_child_with_output.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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

        command = "start_child_that_fails.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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

        command = "create_file.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
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
        command = "produce_output"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
exec &> {0}
echo {1}
>&2 echo {2}

'''.format(command_output_file, stdout, stderr))

        output = self.ext_handler_instance.launch_command(command)

        self.assertRegex(output, LaunchCommandTestCase._output_regex('', ''))

        with open(command_output_file, "r") as command_output:
            output = command_output.read()
            self.assertEqual(output, "{0}\n{1}\n".format(stdout, stderr))

    def test_it_should_truncate_the_command_output(self):
        stdout = "STDOUT"
        stderr = "STDERR"

        command = "produce_long_output.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
import sys

sys.stdout.write( "{0}" * {1})
sys.stderr.write( "{2}" * {3})
'''.format(stdout, int(TELEMETRY_MESSAGE_MAX_LEN / len(stdout)), stderr, int(TELEMETRY_MESSAGE_MAX_LEN / len(stderr))))

        output = self.ext_handler_instance.launch_command(command)

        self.assertLessEqual(len(output), TELEMETRY_MESSAGE_MAX_LEN)
        self.assertIn(stdout, output)
        self.assertIn(stderr, output)

    def test_it_should_read_only_the_head_of_large_outputs(self):
        command = "produce_long_output.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
import sys

sys.stdout.write("O" * 5 * 1024 * 1024)
sys.stderr.write("E" * 5 * 1024 * 1024)
''')

        # Mocking the call to file.read() is difficult, so instead we mock the call to format_stdout_stderr, which takes the
        # return value of the calls to file.read(). The intention of the test is to verify we never read (and load in memory)
        # more than a few KB of data from the files used to capture stdout/stderr
        with patch('azurelinuxagent.common.utils.extensionprocessutil.format_stdout_stderr', side_effect=format_stdout_stderr) as mock_format:
            output = self.ext_handler_instance.launch_command(command)

        self.assertGreaterEqual(len(output), 1024)
        self.assertLessEqual(len(output), TELEMETRY_MESSAGE_MAX_LEN)

        mock_format.assert_called_once()

        args, kwargs = mock_format.call_args  # pylint: disable=unused-variable
        stdout, stderr = args

        self.assertGreaterEqual(len(stdout), 1024)
        self.assertLessEqual(len(stdout), TELEMETRY_MESSAGE_MAX_LEN)

        self.assertGreaterEqual(len(stderr), 1024)
        self.assertLessEqual(len(stderr), TELEMETRY_MESSAGE_MAX_LEN)

    def test_it_should_handle_errors_while_reading_the_command_output(self):
        command = "produce_output.py"
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), command), '''
import sys

sys.stdout.write("STDOUT")
sys.stderr.write("STDERR")
''')
        # Mocking the call to file.read() is difficult, so instead we mock the call to_capture_process_output,
        # which will call file.read() and we force stdout/stderr to be None; this will produce an exception when
        # trying to use these files.
        original_capture_process_output = read_output

        def capture_process_output(stdout_file, stderr_file):  # pylint: disable=unused-argument
            return original_capture_process_output(None, None)

        with patch('azurelinuxagent.common.utils.extensionprocessutil.read_output', side_effect=capture_process_output):
            output = self.ext_handler_instance.launch_command(command)

        self.assertIn("[stderr]\nCannot read stdout/stderr:", output)

    def test_it_should_contain_all_helper_environment_variables(self):

        wire_ip = str(uuid.uuid4())
        ext_handler_instance = ExtHandlerInstance(ext_handler=self.ext_handler, protocol=WireProtocol(wire_ip))

        helper_env_vars = {ExtCommandEnvVariable.ExtensionSeqNumber: ext_handler_instance.get_seq_no(),
                           ExtCommandEnvVariable.ExtensionPath: self.tmp_dir,
                           ExtCommandEnvVariable.ExtensionVersion: ext_handler_instance.ext_handler.properties.version,
                           ExtCommandEnvVariable.WireProtocolAddress: wire_ip}

        command = """
            printenv | grep -E '(%s)'
        """ % '|'.join(helper_env_vars.keys())

        test_file = 'printHelperEnvironments.sh'
        self.create_script(os.path.join(self.ext_handler_instance.get_base_dir(), test_file), command)

        with patch("subprocess.Popen", wraps=subprocess.Popen) as patch_popen:
            output = ext_handler_instance.launch_command(test_file)

            args, kwagrs = patch_popen.call_args  # pylint: disable=unused-variable
            without_os_env = dict((k, v) for (k, v) in kwagrs['env'].items() if k not in os.environ)

            # This check will fail if any helper environment variables are added/removed later on
            self.assertEqual(helper_env_vars, without_os_env)

            # This check is checking if the expected values are set for the extension commands
            for helper_var in helper_env_vars:
                self.assertIn("%s=%s" % (helper_var, helper_env_vars[helper_var]), output)
