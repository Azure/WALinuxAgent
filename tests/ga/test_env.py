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
from azurelinuxagent.common.osutil.default import DefaultOSUtil, shellutil
from azurelinuxagent.ga.env import EnvHandler
from tests.tools import AgentTestCase, patch


class TestEnvHandler(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        # save the original run_command so that mocks can reference it
        self.shellutil_run_command = shellutil.run_command

        # save an instance of the original DefaultOSUtil so that mocks can reference it
        self.default_osutil = DefaultOSUtil()

        # AgentTestCase.setUp mocks osutil.factory._get_osutil; we override that mock for this class with a new mock
        # that always returns the default implementation.
        self.mock_get_osutil = patch("azurelinuxagent.common.osutil.factory._get_osutil", return_value=DefaultOSUtil())
        self.mock_get_osutil.start()

    def tearDown(self):
        self.mock_get_osutil.stop()
        AgentTestCase.tearDown(self)

    def test_get_dhcp_client_pid_should_return_a_sorted_list_of_pids(self):
        with patch("azurelinuxagent.common.utils.shellutil.run_command", return_value="11 9 5 22 4 6"):
            pids = EnvHandler().get_dhcp_client_pid()
            self.assertEqual(pids, [4, 5, 6, 9, 11, 22])

    def test_get_dhcp_client_pid_should_return_an_empty_list_and_log_a_warning_when_dhcp_client_is_not_running(self):
        with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
            with patch('azurelinuxagent.common.logger.Logger.warn') as mock_warn:
                pids = EnvHandler().get_dhcp_client_pid()

        self.assertEqual(pids, [])

        self.assertEqual(mock_warn.call_count, 1)
        args, kwargs = mock_warn.call_args # pylint: disable=unused-variable
        message = args[0]
        self.assertEqual("Dhcp client is not running.", message)

    def test_get_dhcp_client_pid_should_return_and_empty_list_and_log_an_error_when_an_invalid_command_is_used(self):
        with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["non-existing-command"])):
            with patch('azurelinuxagent.common.logger.Logger.error') as mock_error:
                pids = EnvHandler().get_dhcp_client_pid()

        self.assertEqual(pids, [])

        self.assertEqual(mock_error.call_count, 1)
        args, kwargs = mock_error.call_args # pylint: disable=unused-variable
        self.assertIn("Failed to get the PID of the DHCP client", args[0])
        self.assertIn("No such file or directory", args[1])

    def test_get_dhcp_client_pid_should_not_log_consecutive_errors(self):
        env_handler = EnvHandler()

        with patch('azurelinuxagent.common.logger.Logger.warn') as mock_warn:
            def assert_warnings(count):
                self.assertEqual(mock_warn.call_count, count)

                for call_args in mock_warn.call_args_list:
                    args, kwargs = call_args # pylint: disable=unused-variable
                    self.assertEqual("Dhcp client is not running.", args[0])

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
                # it should log the first error
                pids = env_handler.get_dhcp_client_pid()
                self.assertEqual(pids, [])
                assert_warnings(1)

                # it should not log subsequent errors
                for i in range(0, 3): # pylint: disable=unused-variable
                    pids = env_handler.get_dhcp_client_pid()
                    self.assertEqual(pids, [])
                    self.assertEqual(mock_warn.call_count, 1)

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", return_value="123"):
                # now it should succeed
                pids = env_handler.get_dhcp_client_pid()
                self.assertEqual(pids, [123])
                assert_warnings(1)

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
                # it should log the new error
                pids = env_handler.get_dhcp_client_pid()
                self.assertEqual(pids, [])
                assert_warnings(2)

                # it should not log subsequent errors
                for i in range(0, 3):
                    pids = env_handler.get_dhcp_client_pid()
                    self.assertEqual(pids, [])
                    self.assertEqual(mock_warn.call_count, 2)

    def test_handle_dhclient_restart_should_reconfigure_network_routes_when_dhcp_client_restarts(self):
        with patch("azurelinuxagent.common.dhcp.DhcpHandler.conf_routes") as mock_conf_routes:
            env_handler = EnvHandler()

            #
            # before the first call to handle_dhclient_restart, EnvHandler configures the network routes and initializes the DHCP PIDs
            #
            with patch.object(env_handler, "get_dhcp_client_pid", return_value=[123]):
                env_handler.dhcp_handler.conf_routes()
                env_handler.dhcp_id_list = env_handler.get_dhcp_client_pid()
                self.assertEqual(mock_conf_routes.call_count, 1)

            #
            # if the dhcp client has not been restarted then it should not reconfigure the network routes
            #
            def mock_check_pid_alive(pid):
                if pid == 123:
                    return True
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(env_handler, "get_dhcp_client_pid", side_effect=Exception("get_dhcp_client_pid should not have been invoked")):
                    env_handler.handle_dhclient_restart()
                    self.assertEqual(mock_conf_routes.call_count, 1)  # count did not change

            #
            # if the process was restarted then it should reconfigure the network routes
            #
            def mock_check_pid_alive(pid): # pylint: disable=function-redefined
                if pid == 123:
                    return False
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(env_handler, "get_dhcp_client_pid", return_value=[456, 789]):
                    env_handler.handle_dhclient_restart()
                    self.assertEqual(mock_conf_routes.call_count, 2)  # count increased

            #
            # if the new dhcp client has not been restarted then it should not reconfigure the network routes
            #
            def mock_check_pid_alive(pid): # pylint: disable=function-redefined
                if pid in [456, 789]:
                    return True
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(env_handler, "get_dhcp_client_pid", side_effect=Exception("get_dhcp_client_pid should not have been invoked")):
                    env_handler.handle_dhclient_restart()
                    self.assertEqual(mock_conf_routes.call_count, 2)  # count did not change
