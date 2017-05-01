# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

from azurelinuxagent.daemon import *
from azurelinuxagent.daemon.main import OPENSSL_FIPS_ENVIRONMENT
from tests.tools import *


class MockDaemonCall(object):
    def __init__(self, daemon_handler, count):
        self.daemon_handler = daemon_handler
        self.count = count

    def __call__(self, *args, **kw):
        self.count = self.count - 1
        #Stop daemon after restarting for n times
        if self.count <= 0:
            self.daemon_handler.running = False
        raise Exception("Mock unhandled exception")

class TestDaemon(AgentTestCase):
    
    @patch("time.sleep")
    def test_daemon_restart(self, mock_sleep):
        #Mock daemon function
        daemon_handler = get_daemon_handler()
        mock_daemon = Mock(side_effect=MockDaemonCall(daemon_handler, 2))
        daemon_handler.daemon = mock_daemon

        daemon_handler.check_pid = Mock()
 
        daemon_handler.run()

        mock_sleep.assert_any_call(15)
        self.assertEquals(2, daemon_handler.daemon.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.daemon.main.conf")
    @patch("azurelinuxagent.daemon.main.sys.exit")
    def test_check_pid(self, mock_exit, mock_conf, mock_sleep):
        daemon_handler = get_daemon_handler()

        mock_pid_file = os.path.join(self.tmp_dir, "pid")
        mock_conf.get_agent_pid_file_path = Mock(return_value=mock_pid_file)

        daemon_handler.check_pid()
        self.assertTrue(os.path.isfile(mock_pid_file))

        daemon_handler.check_pid()
        mock_exit.assert_any_call(0)

    @patch("azurelinuxagent.daemon.main.DaemonHandler.check_pid")
    @patch("azurelinuxagent.common.conf.get_fips_enabled", return_value=True)
    def test_set_openssl_fips(self, mock_conf, mock_daemon):
        daemon_handler = get_daemon_handler()
        daemon_handler.running = False
        with patch.dict("os.environ"):
            daemon_handler.run()
            self.assertTrue(OPENSSL_FIPS_ENVIRONMENT in os.environ)
            self.assertEqual('1', os.environ[OPENSSL_FIPS_ENVIRONMENT])

    @patch("azurelinuxagent.daemon.main.DaemonHandler.check_pid")
    @patch("azurelinuxagent.common.conf.get_fips_enabled", return_value=False)
    def test_does_not_set_openssl_fips(self, mock_conf, mock_daemon):
        daemon_handler = get_daemon_handler()
        daemon_handler.running = False
        with patch.dict("os.environ"):
            daemon_handler.run()
            self.assertFalse(OPENSSL_FIPS_ENVIRONMENT in os.environ)
   
if __name__ == '__main__':
    unittest.main()

