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
import datetime
import stat
import subprocess

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common.utils.processutil \
    import format_stdout_stderr, capture_from_process
from tests.tools import *
import sys

process_target = "{0}/process_target.sh".format(os.path.abspath(os.path.join(__file__, os.pardir)))
process_cmd_template = "{0} -o '{1}' -e '{2}'"

EXTENSION_ERROR_CODE = 1000

class TestProcessUtils(AgentTestCase):
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


class CaptureFromProcessTestCase(AgentTestCase):
    """
    Test cases for capture_from_process
    """
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        cls.test_directory = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_directory)

    def create_command(self, command_file, contents):
        """
        Creates an executable file with the given contents
        """
        command_path = os.path.join(self.test_directory, command_file)

        with open(command_path, "w") as file:
            file.write(contents)

        os.chmod(command_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        return command_path

    @staticmethod
    def create_subprocess(cmd):
        """
        Wrapper around subprocess.Popen; the subprocess is created as its group leader
        """
        return subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ,
            preexec_fn=os.setsid)

    def test_it_should_capture_the_output_if_process_is_not_leader_and_timeout_is_not_given(self):
        """
        If the command has no timeout, the process need not be the leader of its own process group.
        """
        stdout = "The quick brown fox jumps over the lazy dog.\n"
        stderr = "The five boxing wizards jump quickly.\n"

        expected = "[stdout]\n{0}\n\n[stderr]\n{1}".format(stdout, stderr)

        cmd = process_cmd_template.format(process_target, stdout, stderr)
        process = subprocess.Popen(cmd,
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   env=os.environ)

        actual = capture_from_process(process, cmd)
        self.assertEqual(expected, actual)

    def test_it_should_throw_if_process_is_not_leader_and_timeout_is_given(self):
        """
        If a timeout is requested but the process is not the root of the process group, raise an exception.
        """
        stdout = "stdout\n"
        stderr = "stderr\n"

        cmd = process_cmd_template.format(process_target, stdout, stderr)
        process = subprocess.Popen(cmd,
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   env=os.environ)

        if sys.version_info < (2, 7):
            self.assertRaises(ExtensionError, capture_from_process, process, cmd, 10, EXTENSION_ERROR_CODE)
        else:
            with self.assertRaises(ExtensionError) as ee:
                capture_from_process(process, cmd, 10, EXTENSION_ERROR_CODE)

            body = str(ee.exception)
            if sys.version_info >= (3, 2):
                self.assertRegex(body, "process group")
            else:
                self.assertRegexpMatches(body, "process group")

            self.assertEqual(EXTENSION_ERROR_CODE, ee.exception.code)

    def test_it_should_capture_the_output_of_timed_out_process(self):
        """
        non-forked process runs for 20 seconds, timeout is 10 seconds
        we expect:
            - test to run in just over 10 seconds
            - exception should be thrown
            - output should be collected
        """
        process = CaptureFromProcessTestCase.create_subprocess("{0} -t 20".format(process_target))

        try:
            capture_from_process(process, 'sleep 20', 10, EXTENSION_ERROR_CODE)
            self.fail('Timeout exception was expected')
        except ExtensionError as e:
            body = str(e)
            self.assertTrue('Timeout(10)' in body)
            self.assertTrue('Iteration 9' in body)
            self.assertFalse('Iteration 11' in body)
            self.assertEqual(EXTENSION_ERROR_CODE, e.code)
        except Exception as gen_ex:
            self.fail('Unexpected exception: {0}'.format(gen_ex))

    def test_it_should_capture_the_output_of_forked_process(self):
        """
        forked process runs for 20 seconds, timeout is 10 seconds
        we expect:
            - test to run in less than 3 seconds
            - no exception should be thrown
            - collects the beginning of the output of the forked process
        """
        process = CaptureFromProcessTestCase.create_subprocess("{0} -t 20 &".format(process_target))

        start = datetime.datetime.utcnow()
        try:
            cap = capture_from_process(process, 'sleep 20 &', 10)
        except Exception as e:
            self.fail('No exception should be thrown for a long running process which forks: {0}'.format(e))
        duration = datetime.datetime.utcnow() - start

        self.assertTrue(duration < datetime.timedelta(seconds=3))
        self.assertIn('[stdout]\nIteration 1\n', cap)

    def test_it_should_capture_the_output_of_process_that_completes_within_timeout(self):
        """
        non-forked process runs for 10 seconds, timeout is 20 seconds
        we expect:
            - test to run in just over 10 seconds
            - no exception should be thrown
            - output should be collected
        """
        process = CaptureFromProcessTestCase.create_subprocess("{0} -t 10".format(process_target))

        try:
            body = capture_from_process(process, 'sleep 10', 20)
        except Exception as gen_ex:
            self.fail('Unexpected exception: {0}'.format(gen_ex))

        self.assertFalse('Timeout' in body)
        self.assertTrue('Iteration 9' in body)
        self.assertTrue('Iteration 10' in body)

    def test_it_should_capture_the_output_of_forked_process_that_completes_within_timeout(self):
        """
        forked process runs for 10 seconds, timeout is 20 seconds
        we expect:
            - test to run in under 3 seconds
            - no exception should be thrown
            - collects the beginning of the output of the forked process (up to a second)
        """
        process = CaptureFromProcessTestCase.create_subprocess("{0} -t 10 &".format(process_target))

        start = datetime.datetime.utcnow()
        try:
            body = capture_from_process(process, 'sleep 10 &', 20)
        except Exception as e:
            self.fail('No exception should be thrown for a well behaved process which forks: {0}'.format(e))
        duration = datetime.datetime.utcnow() - start

        self.assertTrue(duration < datetime.timedelta(seconds=3))
        self.assertIn('[stdout]\nIteration 1\n', body)

    def test_it_should_capture_the_output_of_child_processes(self, *_unused):
        command = self.create_command("create_output_with_fork.py", '''#!/usr/bin/env python3
import os
import sys
import time

sys.stdout.write("PARENT STDOUT\\n")
sys.stderr.write("PARENT STDERR\\n")

pid = os.fork()
if pid == 0:
    sys.stdout.write("CHILD STDOUT\\n")
    sys.stderr.write("CHILD STDERR\\n")
else:
    sys.stdout.write("MORE PARENT STDOUT\\n")
    sys.stderr.write("MORE PARENT STDERR\\n")
''')

        process = CaptureFromProcessTestCase.create_subprocess(command)

        output = capture_from_process(process, command, 60)

        self.assertIn("PARENT STDOUT", output)
        self.assertIn("PARENT STDERR", output)

        self.assertIn("CHILD STDOUT", output)
        self.assertIn("CHILD STDERR", output)

        self.assertIn("MORE PARENT STDOUT", output)
        self.assertIn("MORE PARENT STDERR", output)

    def test_it_should_not_wait_for_child_processes_if_a_timeout_is_given(self, *_unused):
        command = self.create_command("create_output_after_10_sec.py", '''#!/usr/bin/env python3
import os
import sys
import time

pid = os.fork()
if pid == 0:
    time.sleep(10)
    sys.stdout.write("CHILD STDOUT\\n")
    sys.stderr.write("CHILD STDERR\\n")
''')
        start = datetime.datetime.utcnow()

        process = CaptureFromProcessTestCase.create_subprocess(command)

        output = capture_from_process(process, command, 60)

        duration = datetime.datetime.utcnow() - start

        self.assertTrue(duration < datetime.timedelta(seconds=5))
        self.assertNotIn("CHILD STDOUT", output)
        self.assertNotIn("CHILD STDERR", output)

    def test_it_should_handle_processes_with_no_output(self, *_unused):
        command = self.create_command("sleep_one_second.py", '''#!/usr/bin/env python3
import time

time.sleep(1)
''')

        process = CaptureFromProcessTestCase.create_subprocess(command)

        output = capture_from_process(process, command, 60)

        self.assertEqual('[stdout]\n\n\n[stderr]\n', output)

    def test_it_should_capture_the_last_1K_of_output(self, *_unused):
        command = self.create_command("sleep_one_second.py", '''#!/usr/bin/env python3
import sys

sys.stdout.write( 'A' * 1024 + 'B' * 512)
sys.stderr.write( 'C' * 1024 + 'D' * 512)
''')

        process = CaptureFromProcessTestCase.create_subprocess(command)

        output = capture_from_process(process, command, 60)

        stdout = 'A' * 512 + 'B' * 512
        stderr = 'C' * 512 + 'D' * 512
        expected = '[stdout]\n{0}\n\n[stderr]\n{1}'.format(stdout, stderr)

        self.assertEqual(expected, output)

