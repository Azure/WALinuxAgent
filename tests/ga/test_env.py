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

from azurelinuxagent.common.future import UTC
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil, shellutil
from azurelinuxagent.ga.env import MonitorDhcpClientRestart, EnableFirewall, FirewallState
from azurelinuxagent.ga.firewall_manager import IptablesInconsistencyError

from tests.lib.tools import AgentTestCase, patch, Mock
from tests.lib.mock_firewall_command import MockIpTables


class MonitorDhcpClientRestartTestCase(AgentTestCase):
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
            pids = MonitorDhcpClientRestart(get_osutil())._get_dhcp_client_pid()
            self.assertEqual(pids, [4, 5, 6, 9, 11, 22])

    def test_get_dhcp_client_pid_should_return_an_empty_list_and_log_a_warning_when_dhcp_client_is_not_running(self):
        with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
            with patch('azurelinuxagent.common.logger.Logger.warn') as mock_warn:
                pids = MonitorDhcpClientRestart(get_osutil())._get_dhcp_client_pid()

        self.assertEqual(pids, [])

        self.assertEqual(mock_warn.call_count, 1)
        args, kwargs = mock_warn.call_args  # pylint: disable=unused-variable
        message = args[0]
        self.assertEqual("Dhcp client is not running.", message)

    def test_get_dhcp_client_pid_should_return_and_empty_list_and_log_an_error_when_an_invalid_command_is_used(self):
        with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["non-existing-command"])):
            with patch('azurelinuxagent.common.logger.Logger.error') as mock_error:
                pids = MonitorDhcpClientRestart(get_osutil())._get_dhcp_client_pid()

        self.assertEqual(pids, [])

        self.assertEqual(mock_error.call_count, 1)
        args, kwargs = mock_error.call_args  # pylint: disable=unused-variable
        self.assertIn("Failed to get the PID of the DHCP client", args[0])
        self.assertIn("No such file or directory", args[1])

    def test_get_dhcp_client_pid_should_not_log_consecutive_errors(self):
        monitor_dhcp_client_restart = MonitorDhcpClientRestart(get_osutil())

        with patch('azurelinuxagent.common.logger.Logger.warn') as mock_warn:
            def assert_warnings(count):
                self.assertEqual(mock_warn.call_count, count)

                for call_args in mock_warn.call_args_list:
                    args, _ = call_args
                    self.assertEqual("Dhcp client is not running.", args[0])

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
                # it should log the first error
                pids = monitor_dhcp_client_restart._get_dhcp_client_pid()
                self.assertEqual(pids, [])
                assert_warnings(1)

                # it should not log subsequent errors
                for _ in range(0, 3):
                    pids = monitor_dhcp_client_restart._get_dhcp_client_pid()
                    self.assertEqual(pids, [])
                    self.assertEqual(mock_warn.call_count, 1)

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", return_value="123"):
                # now it should succeed
                pids = monitor_dhcp_client_restart._get_dhcp_client_pid()
                self.assertEqual(pids, [123])
                assert_warnings(1)

            with patch("azurelinuxagent.common.osutil.default.shellutil.run_command", side_effect=lambda _: self.shellutil_run_command(["pidof", "non-existing-process"])):
                # it should log the new error
                pids = monitor_dhcp_client_restart._get_dhcp_client_pid()
                self.assertEqual(pids, [])
                assert_warnings(2)

                # it should not log subsequent errors
                for _ in range(0, 3):
                    pids = monitor_dhcp_client_restart._get_dhcp_client_pid()
                    self.assertEqual(pids, [])
                    self.assertEqual(mock_warn.call_count, 2)

    def test_handle_dhclient_restart_should_reconfigure_network_routes_when_dhcp_client_restarts(self):
        with patch("azurelinuxagent.common.dhcp.DhcpHandler.conf_routes") as mock_conf_routes:
            monitor_dhcp_client_restart = MonitorDhcpClientRestart(get_osutil())
            monitor_dhcp_client_restart._period = datetime.timedelta(seconds=0)

            # Run the operation one time to initialize the DHCP PIDs
            with patch.object(monitor_dhcp_client_restart, "_get_dhcp_client_pid", return_value=[123]):
                monitor_dhcp_client_restart.run()

            #
            # if the dhcp client has not been restarted then it should not reconfigure the network routes
            #
            def mock_check_pid_alive(pid):
                if pid == 123:
                    return True
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(monitor_dhcp_client_restart, "_get_dhcp_client_pid", side_effect=Exception("get_dhcp_client_pid should not have been invoked")):
                    monitor_dhcp_client_restart.run()
                    self.assertEqual(mock_conf_routes.call_count, 1)  # count did not change

            #
            # if the process was restarted then it should reconfigure the network routes
            #
            def mock_check_pid_alive(pid):  # pylint: disable=function-redefined
                if pid == 123:
                    return False
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(monitor_dhcp_client_restart, "_get_dhcp_client_pid", return_value=[456, 789]):
                    monitor_dhcp_client_restart.run()
                    self.assertEqual(mock_conf_routes.call_count, 2)  # count increased

            #
            # if the new dhcp client has not been restarted then it should not reconfigure the network routes
            #
            def mock_check_pid_alive(pid):  # pylint: disable=function-redefined
                if pid in [456, 789]:
                    return True
                raise Exception("Unexpected PID: {0}".format(pid))

            with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.check_pid_alive", side_effect=mock_check_pid_alive):
                with patch.object(monitor_dhcp_client_restart, "_get_dhcp_client_pid", side_effect=Exception("get_dhcp_client_pid should not have been invoked")):
                    monitor_dhcp_client_restart.run()
                    self.assertEqual(mock_conf_routes.call_count, 2)  # count did not change


class TestEnableFirewall(AgentTestCase):
    def test_it_should_restore_missing_firewall_rules(self):
        with MockIpTables() as mock_iptables:
            enable_firewall = EnableFirewall('168.63.129.16')

            test_cases = [  # Exit codes for the "-C" (check) command
                {"accept_dns": 1, "accept": 0, "drop": 0, "legacy": 0},
                {"accept_dns": 0, "accept": 1, "drop": 0, "legacy": 0},
                {"accept_dns": 0, "accept": 1, "drop": 0, "legacy": 0},
                {"accept_dns": 1, "accept": 1, "drop": 1, "legacy": 0},
            ]

            for test_case in test_cases:
                mock_iptables.set_return_values("-C", **test_case)

                enable_firewall.run()

                self.assertEqual(
                    [
                        mock_iptables.get_accept_dns_command("-A"),
                        mock_iptables.get_accept_command("-A"),
                        mock_iptables.get_drop_command("-A"),
                        mock_iptables.get_list_command(),
                    ],
                    mock_iptables.call_list[-4:],
                    "Expected the 3 firewall rules to be restored (Test case: {0})".format(test_case))

    def test_it_should_not_modify_the_firewall_rules_when_the_check_command_is_inconsistent_with_the_list_command(self):
        with MockIpTables(check_matches_list=False) as mock_iptables:
            enable_firewall = EnableFirewall('168.63.129.16')

            test_cases = [  # Exit codes for the "-C" (check) command
                {"accept_dns": 1, "accept": 0, "drop": 0, "legacy": 0},
                {"accept_dns": 0, "accept": 1, "drop": 0, "legacy": 0},
                {"accept_dns": 0, "accept": 1, "drop": 0, "legacy": 0},
                {"accept_dns": 1, "accept": 1, "drop": 1, "legacy": 0},
            ]

            for test_case in test_cases:
                mock_iptables.set_return_values("-C", **test_case)

                enable_firewall.run()

                self.assertFalse(any("-D" in command or "-A" in command for command in mock_iptables.call_list), "The -D or -A commands should not have been invoked (Test case: {0}). Commands: {1}".format(test_case, mock_iptables.call_list))

                self.assertEqual(
                    [
                        mock_iptables.get_accept_dns_command("-C"),
                        mock_iptables.get_accept_command("-C"),
                        mock_iptables.get_drop_command("-C"),
                    ],
                    mock_iptables.call_list[:3],
                    "Expected the 3 firewall rules to have been checked (Test case: {0})".format(test_case))

    # These messages are used multiple times in the tests below. Each message is a tuple of (is_success, message) as used by the telemetry event emitted by the Agent.
    _FIREWALL_OK_MESSAGE = (True, 'The firewall is configured correctly. Current state:\n*** mock state***')
    _FIREWALL_INCONSISTENT_MESSAGE = (False, "[WARNING] The results returned by iptables are inconsistent, will not change the current state of the firewall: Inconsistent results from iptables: -C reports that some rules are missing (['NONE']), but -L shows some of them exist:\nSimulated inconsistency")

    _FIREWALL_OK_STATE = "*** mock state***"
    _FIREWALL_INCONSISTENT_EXCEPTION = IptablesInconsistencyError(missing_rules=["NONE"], output_chain="Simulated inconsistency")

    @staticmethod
    def _get_firewall_events(add_event_mock):
        """Extracts is_success and message from the telemetry events related to the firewall"""
        return [(kwargs["is_success"], kwargs['message']) for _, kwargs in add_event_mock.call_args_list if 'Firewall' in kwargs["op"]]
    

    def test_it_should_log_only_once_per_reporting_period_when_the_state_of_the_firewall_is_correct(self):
        enable_firewall = EnableFirewall('168.63.129.16')

        enable_firewall._firewall_manager = Mock()
        enable_firewall._firewall_manager.check = Mock(return_value=True)
        enable_firewall._firewall_manager.get_state = Mock(return_value=TestEnableFirewall._FIREWALL_OK_STATE)

        expected = [TestEnableFirewall._FIREWALL_OK_MESSAGE]

        with patch("azurelinuxagent.common.event.add_event") as add_event_patch:
            #
            # First reporting period
            #
            for _ in range(0, 10):
                enable_firewall._operation()  # we call the _operation() method directly because the run() method enforces its own time period

            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the first reporting period")
            
            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "Expected only one report during the first reporting period")

            # Mark the end of the reporting period
            enable_firewall._reporting_period_end = datetime.datetime.now(UTC)

            #
            # Second reporting period
            #
            enable_firewall._firewall_manager.check.reset_mock()
            add_event_patch.reset_mock()

            for _ in range(0, 10):
                enable_firewall._operation()
            
            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the second reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "Expected only one report during the second reporting period")


    def test_it_should_log_only_three_times_per_reporting_period_when_the_state_of_the_firewall_is_incorrect(self):
        enable_firewall = EnableFirewall('168.63.129.16')

        enable_firewall._firewall_manager = Mock()
        enable_firewall._firewall_manager.check = Mock(side_effect=TestEnableFirewall._FIREWALL_INCONSISTENT_EXCEPTION)
        enable_firewall._firewall_state = FirewallState.Inconsistent  # Initialize to inconsistent to avoid an extra state change

        expected = EnableFirewall._MAX_REPORTS_WHEN_FIREWALL_NOT_OK * [TestEnableFirewall._FIREWALL_INCONSISTENT_MESSAGE]

        with patch("azurelinuxagent.common.event.add_event") as add_event_patch:
            #
            # First reporting period
            #
            for _ in range(0, 10):
                enable_firewall._operation()  # we call the _operation() method directly because the run() method enforces its own time period

            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the first reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "Expected only three reports during the first reporting period")

            # Mark the end of the reporting period
            enable_firewall._reporting_period_end = datetime.datetime.now(UTC)

            #
            # Second reporting period
            #
            enable_firewall._firewall_manager.check.reset_mock()
            add_event_patch.reset_mock()

            for _ in range(0, 10):
                enable_firewall._operation()

            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the second reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "Expected only three reports during the second reporting period")
            
    
    def test_it_should_set_a_limit_on_the_number_of_reports_when_the_firewall_state_changes(self):
        enable_firewall = EnableFirewall('168.63.129.16')

        def mock_check(*_, **__):
            mock_check.firewall_ok = not mock_check.firewall_ok  # flip the state of the firewall on every call
            if mock_check.firewall_ok:
                return True
            else:
                raise TestEnableFirewall._FIREWALL_INCONSISTENT_EXCEPTION
        mock_check.firewall_ok = False

        enable_firewall._firewall_manager = Mock()
        enable_firewall._firewall_manager.check = Mock(side_effect=mock_check)
        enable_firewall._firewall_manager.get_state = Mock(return_value=TestEnableFirewall._FIREWALL_OK_STATE)

        # We expect a maximum of 8 reports for each reporting period. The mock for check() flips between correct and incorrect firewall state on every call, so we expect a success and a failure repeated four times.
        expected = EnableFirewall._MAX_REPORTS_PER_PERIOD // 2 * [ TestEnableFirewall._FIREWALL_OK_MESSAGE, TestEnableFirewall._FIREWALL_INCONSISTENT_MESSAGE ]

        with patch("azurelinuxagent.common.event.add_event") as add_event_patch:
            #
            # First reporting period
            #
            for _ in range(0, 10):
                enable_firewall._operation()

            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the first reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "First reporting period: Expected 8 reports, 1 INFO (is_success == True) and 1 WARNING (is_success == False) alternating 4 times")

            # Mark the end of the reporting period
            enable_firewall._reporting_period_end = datetime.datetime.now(UTC)

            #
            # Second reporting period
            #
            enable_firewall._firewall_manager.check.reset_mock()
            add_event_patch.reset_mock()

            for _ in range(0, 10):
                enable_firewall._operation()

            self.assertEqual(10, enable_firewall._firewall_manager.check.call_count, "Expected 10 calls to FirewallManager.check() during the second reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "Second reporting period: Expected 8 reports, 1 INFO (is_success == True) and 1 WARNING (is_success == False) alternating 4 times")

    def test_it_should_reset_the_count_of_reports_when_the_firewall_state_changes(self):
        enable_firewall = EnableFirewall('168.63.129.16')

        def mock_check(*_, **__):
            # Return a correct state five times, then report an incorrect state five times, then repeat.
            if ((enable_firewall._firewall_manager.check.call_count - 1) // 5) % 2 == 0:
                return True
            else:
                raise TestEnableFirewall._FIREWALL_INCONSISTENT_EXCEPTION

        enable_firewall._firewall_manager = Mock()
        enable_firewall._firewall_manager.check = Mock(side_effect=mock_check)
        enable_firewall._firewall_manager.get_state = Mock(return_value=TestEnableFirewall._FIREWALL_OK_STATE)

        #
        # We expect a maximum of 8 reports per reporting period. The mock for check() flips every five calls between reporting success and failure, so we expect the limits on success and error reports, 1 and 3 respectively,
        # to be reached during each set of 5 calls.
        #
        expected = (
            EnableFirewall._MAX_REPORTS_WHEN_FIREWALL_OK * [TestEnableFirewall._FIREWALL_OK_MESSAGE] + 
            EnableFirewall._MAX_REPORTS_WHEN_FIREWALL_NOT_OK * [TestEnableFirewall._FIREWALL_INCONSISTENT_MESSAGE] +
            EnableFirewall._MAX_REPORTS_WHEN_FIREWALL_OK * [TestEnableFirewall._FIREWALL_OK_MESSAGE] + 
            EnableFirewall._MAX_REPORTS_WHEN_FIREWALL_NOT_OK * [TestEnableFirewall._FIREWALL_INCONSISTENT_MESSAGE]
        )

        with patch("azurelinuxagent.common.event.add_event") as add_event_patch:
            for _ in range(0, 20):
                enable_firewall._operation()

            self.assertEqual(20, enable_firewall._firewall_manager.check.call_count, "Expected 20 calls to FirewallManager.check() during the first reporting period")

            actual = self._get_firewall_events(add_event_patch)
            self.assertEqual(expected, actual, "First reporting period: Expected 1 INFO (is_success == True) then 3 WARNINGs (is_success == False), repeated 2 times")
