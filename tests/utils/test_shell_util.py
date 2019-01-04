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
import uuid
import unittest
import os
import azurelinuxagent.common.utils.shellutil as shellutil
import test

class TestrunCmd(AgentTestCase):
    def test_run_get_output(self):
        output = shellutil.run_get_output(u"ls /")
        self.assertNotEquals(None, output)
        self.assertEquals(0, output[0])

        err = shellutil.run_get_output(u"ls /not-exists")
        self.assertNotEquals(0, err[0])
            
        err = shellutil.run_get_output(u"ls 我")
        self.assertNotEquals(0, err[0])

    def test_shellquote(self):
        self.assertEqual("\'foo\'", shellutil.quote("foo"))
        self.assertEqual("\'foo bar\'", shellutil.quote("foo bar"))
        self.assertEqual("'foo'\\''bar'", shellutil.quote("foo\'bar"))

    def test_it_should_log_command_failures_as_errors(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger.error") as mock_error:
            shellutil.run_get_output(command)

        mock_error.assert_called_once()

        args, kwargs = mock_error.call_args
        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

    def test_it_should_log_expected_errors_as_info(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger.info") as mock_info:
            shellutil.run_get_output(command, expected_errors=[return_code])

        mock_info.assert_called_once()

        args, kwargs = mock_info.call_args
        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)

    def test_it_should_log_unexpected_errors_as_errors(self):
        return_code = 99
        command = "exit {0}".format(return_code)

        with patch("azurelinuxagent.common.utils.shellutil.logger.error") as mock_error:
            shellutil.run_get_output(command, expected_errors=[return_code + 1])

        mock_error.assert_called_once()

        args, kwargs = mock_error.call_args
        message = args[0]  # message is similar to "Command: [exit 99], return code: [99], result: []"
        self.assertIn("[{0}]".format(command), message)
        self.assertIn("[{0}]".format(return_code), message)


if __name__ == '__main__':
    unittest.main()
