# Copyright 2019 Microsoft Corporation
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
from azurelinuxagent.common.utils.fileutil import read_file
from azurelinuxagent.common.osutil.nsbsd import NSBSDOSUtil
from tests.tools import AgentTestCase, patch
from os import path # pylint: disable=wrong-import-order
import unittest # pylint: disable=wrong-import-order


class TestNSBSDOSUtil(AgentTestCase):
    dhclient_pid_file = "/var/run/dhclient.pid"

    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        with patch.object(NSBSDOSUtil, "resolver"):  # instantiating NSBSDOSUtil requires a resolver
            original_isfile = path.isfile

            def mock_isfile(path): # pylint: disable=redefined-outer-name
                return True if path == self.dhclient_pid_file else original_isfile(path)

            original_read_file = read_file

            def mock_read_file(file, *args, **kwargs): # pylint: disable=redefined-builtin
                return "123" if file == self.dhclient_pid_file else original_read_file(file, *args, **kwargs)

            with patch("os.path.isfile", mock_isfile):
                with patch("azurelinuxagent.common.osutil.nsbsd.fileutil.read_file", mock_read_file):
                    pid_list = NSBSDOSUtil().get_dhcp_pid()

            self.assertEqual(pid_list, [123])

    def test_get_dhcp_pid_should_return_an_empty_list_when_the_dhcp_client_is_not_running(self):
        with patch.object(NSBSDOSUtil, "resolver"):  # instantiating NSBSDOSUtil requires a resolver
            #
            # PID file does not exist
            #
            original_isfile = path.isfile

            def mock_isfile(path): # pylint: disable=redefined-outer-name
                return False if path == self.dhclient_pid_file else original_isfile(path)

            with patch("os.path.isfile", mock_isfile):
                pid_list = NSBSDOSUtil().get_dhcp_pid()

            self.assertEqual(pid_list, [])

            #
            # PID file is empty
            #
            original_isfile = path.isfile

            def mock_isfile(path): # pylint: disable=redefined-outer-name,function-redefined
                return True if path == self.dhclient_pid_file else original_isfile(path)

            original_read_file = read_file

            def mock_read_file(file, *args, **kwargs): # pylint: disable=redefined-builtin
                return "" if file == self.dhclient_pid_file else original_read_file(file, *args, **kwargs)

            with patch("os.path.isfile", mock_isfile):
                with patch("azurelinuxagent.common.osutil.nsbsd.fileutil.read_file", mock_read_file):
                    pid_list = NSBSDOSUtil().get_dhcp_pid()

            self.assertEqual(pid_list, [])


if __name__ == '__main__':
    unittest.main()
