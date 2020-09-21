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

import os
import unittest
from multiprocessing import Process

import azurelinuxagent.common.conf as conf
from azurelinuxagent.daemon.main import OPENSSL_FIPS_ENVIRONMENT, get_daemon_handler
from azurelinuxagent.pa.provision.default import ProvisionHandler
from tests.tools import AgentTestCase, Mock, patch


class MockDaemonCall(object): # pylint: disable=too-few-public-methods
    def __init__(self, daemon_handler, count):
        self.daemon_handler = daemon_handler
        self.count = count

    def __call__(self, *args, **kw):
        self.count = self.count - 1
        # Stop daemon after restarting for n times
        if self.count <= 0:
            self.daemon_handler.running = False
        raise Exception("Mock unhandled exception")


class TestDaemon(AgentTestCase):
    
    @patch("time.sleep")
    def test_daemon_restart(self, mock_sleep):
        # Mock daemon function
        daemon_handler = get_daemon_handler()
        mock_daemon = Mock(side_effect=MockDaemonCall(daemon_handler, 2))
        daemon_handler.daemon = mock_daemon

        daemon_handler.check_pid = Mock()
 
        daemon_handler.run()

        mock_sleep.assert_any_call(15)
        self.assertEqual(2, daemon_handler.daemon.call_count)

    @patch("time.sleep")
    @patch("azurelinuxagent.daemon.main.conf")
    @patch("azurelinuxagent.daemon.main.sys.exit")
    def test_check_pid(self, mock_exit, mock_conf, _):
        daemon_handler = get_daemon_handler()

        mock_pid_file = os.path.join(self.tmp_dir, "pid")
        mock_conf.get_agent_pid_file_path = Mock(return_value=mock_pid_file)

        daemon_handler.check_pid()
        self.assertTrue(os.path.isfile(mock_pid_file))

        daemon_handler.check_pid()
        mock_exit.assert_any_call(0)

    @patch("azurelinuxagent.daemon.main.DaemonHandler.check_pid")
    @patch("azurelinuxagent.common.conf.get_fips_enabled", return_value=True)
    def test_set_openssl_fips(self, _, __):
        daemon_handler = get_daemon_handler()
        daemon_handler.running = False
        with patch.dict("os.environ"):
            daemon_handler.run()
            self.assertTrue(OPENSSL_FIPS_ENVIRONMENT in os.environ)
            self.assertEqual('1', os.environ[OPENSSL_FIPS_ENVIRONMENT])

    @patch("azurelinuxagent.daemon.main.DaemonHandler.check_pid")
    @patch("azurelinuxagent.common.conf.get_fips_enabled", return_value=False)
    def test_does_not_set_openssl_fips(self, _, __):
        daemon_handler = get_daemon_handler()
        daemon_handler.running = False
        with patch.dict("os.environ"):
            daemon_handler.run()
            self.assertFalse(OPENSSL_FIPS_ENVIRONMENT in os.environ)

    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    @patch('azurelinuxagent.ga.update.UpdateHandler.run_latest')
    @patch('azurelinuxagent.pa.provision.default.ProvisionHandler.run')
    def test_daemon_agent_enabled(self, patch_run_provision, patch_run_latest, gpa): # pylint: disable=unused-argument
        """
        Agent should run normally when no disable_agent is found
        """
        with patch('azurelinuxagent.pa.provision.get_provision_handler', return_value=ProvisionHandler()):
            # DaemonHandler._initialize_telemetry requires communication with WireServer and IMDS; since we
            # are not using telemetry in this test we mock it out
            with patch('azurelinuxagent.daemon.main.DaemonHandler._initialize_telemetry'):
                self.assertFalse(os.path.exists(conf.get_disable_agent_file_path()))
                daemon_handler = get_daemon_handler()

                def stop_daemon(child_args): # pylint: disable=unused-argument
                    daemon_handler.running = False

                patch_run_latest.side_effect = stop_daemon
                daemon_handler.run()

                self.assertEqual(1, patch_run_provision.call_count)
                self.assertEqual(1, patch_run_latest.call_count)

    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    @patch('azurelinuxagent.ga.update.UpdateHandler.run_latest', side_effect=AgentTestCase.fail)
    @patch('azurelinuxagent.pa.provision.default.ProvisionHandler.run', side_effect=ProvisionHandler.write_agent_disabled)
    def test_daemon_agent_disabled(self, _, patch_run_latest, gpa): # pylint: disable=unused-argument
        """
        Agent should provision, then sleep forever when disable_agent is found
        """

        with patch('azurelinuxagent.pa.provision.get_provision_handler', return_value=ProvisionHandler()):
            # file is created by provisioning handler
            self.assertFalse(os.path.exists(conf.get_disable_agent_file_path()))
            daemon_handler = get_daemon_handler()

            # we need to assert this thread will sleep forever, so fork it
            daemon = Process(target=daemon_handler.run)
            daemon.start()
            daemon.join(timeout=5)

            self.assertTrue(daemon.is_alive())
            daemon.terminate()

            # disable_agent was written, run_latest was not called
            self.assertTrue(os.path.exists(conf.get_disable_agent_file_path()))
            self.assertEqual(0, patch_run_latest.call_count)


if __name__ == '__main__':
    unittest.main()

