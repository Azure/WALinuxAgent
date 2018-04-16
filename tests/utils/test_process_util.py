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

import subprocess

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common.utils.processutil \
    import format_stdout_stderr, capture_from_process, capture_from_process_raw
from tests.tools import *
import sys

process_target = "tests/utils/process_target.sh"
process_cmd_template = "{0} -o '{1}' -e '{2}'"


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

    def test_process_stdout_stderr(self):
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

    def test_process_timeout(self):
        cmd = "{0} -t 20".format(process_target)
        process = subprocess.Popen(cmd,
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   env=os.environ,
                                   preexec_fn=os.setsid)

        if sys.version_info < (2, 7):
            self.assertRaises(ExtensionError, capture_from_process_raw, process, cmd, 10)
        else:
            with self.assertRaises(ExtensionError) as ee:
                capture_from_process_raw(process, cmd, 10)

            body = str(ee.exception)
            if sys.version_info >= (3, 2):
                self.assertNotRegex(body, "Iteration 12")
                self.assertRegex(body, "Iteration 8")
            else:
                self.assertNotRegexpMatches(body, "Iteration 12")
                self.assertRegexpMatches(body, "Iteration 8")

    def test_process_bad_pgid(self):
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
            self.assertRaises(ExtensionError, capture_from_process, process, cmd, 10)
        else:
            with self.assertRaises(ExtensionError) as ee:
                capture_from_process(process, cmd, 10)

            body = str(ee.exception)
            if sys.version_info >= (3, 2):
                self.assertRegex(body, "process group")
            else:
                self.assertRegexpMatches(body, "process group")


if __name__ == '__main__':
    unittest.main()
