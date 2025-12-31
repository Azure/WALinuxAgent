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
import time

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil, shellutil
from azurelinuxagent.ga.env import MonitorDhcpClientRestart, EnableFirewall

from tests.lib.event import get_events_from_mock
from tests.lib.tools import AgentTestCase, patch, DEFAULT
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

    def test_it_should_log_the_state_of_the_firewall_once_per_reporting_period(self):
        with MockIpTables() as mock_iptables:
            enable_firewall = EnableFirewall('168.63.129.16')
            enable_firewall._REPORTING_PERIOD = datetime.timedelta(milliseconds=500)

            with patch.multiple("azurelinuxagent.ga.firewall_manager.event", info=DEFAULT, warn=DEFAULT, error=DEFAULT) as patches:
                info = patches["info"]
                warn = patches["warn"]
                error = patches["error"]

                for _ in range(0, 3):
                    enable_firewall._operation()  # we call the _operation() method directly because the run() method enforces its own time period
                event_count_first_reporting_period = info.call_count

                time.sleep(0.5)  # let 1 reporting period elapse

                for _ in range(0, 3):
                    enable_firewall._operation()

            # Each call to the _operation() method should have checked each rule, plus listed all the rules
            expected_commands = 6 * [
                mock_iptables.get_accept_dns_command("-C"),
                mock_iptables.get_accept_command("-C"),
                mock_iptables.get_drop_command("-C"),
                mock_iptables.get_list_command()
            ]
            self.assertEqual(expected_commands, mock_iptables.call_list, "Expected commands {0}, got: {1}".format(expected_commands, mock_iptables.call_list))

            # The first call to _operation() reports the version of iptables, then there should be only one firewall state report for each of the 2 reporting periods in the test
            self.assertEqual(2, event_count_first_reporting_period, "Expected 2 events to be logged during the first reporting period, got: {0}".format(info.call_args_list[:event_count_first_reporting_period]))
            self.assertEqual(3, len(info.call_args_list), "Expected a total of 3 events to be logged for the two reporting periods, got: {0}".format(info.call_args_list))
            infos = get_events_from_mock(info)
            self.assertTrue(infos[0][0] == "Firewall" and infos[0][1] == "Using iptables [version 1.4.21] to manage firewall rules", "Expected a check for the iptables version in the first reporting period. Got: {0}".format(infos[0]))
            self.assertTrue(infos[1][0] == "Firewall" and infos[1][1].startswith('The firewall is configured correctly.'), "Expected a firewall status report in the first reporting period. Got: {0}".format(infos[1]))
            self.assertTrue(infos[2][0] == "Firewall" and infos[1][1].startswith('The firewall is configured correctly.'), "Expected a firewall status report in the second reporting period. Got: {0}".format(infos[1]))

            self.assertEqual(0, warn.call_count, "No warnings should have been reported. Got: {0}". format(warn.call_args_list))
            self.assertEqual(0, error.call_count, "No errors should have been reported. Got: {0}". format(error.call_args_list))

    def test_it_should_log_errors_thrice_per_reporting_period(self):
        # We force an inconsistency between "iptables -C" and "iptables -C" to create an error condition (the DROP rule will fail for -C, but will show up in -L)
        with MockIpTables(check_matches_list=False) as mock_iptables:
            mock_iptables.set_return_values("-C", accept_dns=0, accept=0, drop=1, legacy=0)

            enable_firewall = EnableFirewall('168.63.129.16')
            enable_firewall._REPORTING_PERIOD = datetime.timedelta(milliseconds=500)

            firewall_manager_in_verbose_mode = []

            with patch.multiple("azurelinuxagent.ga.firewall_manager.event", info=DEFAULT, warn=DEFAULT, error=DEFAULT) as patches:
                info = patches["info"]
                warn = patches["warn"]
                error = patches["error"]

                for _ in range(0, 5):
                    enable_firewall._operation()  # we call the _operation() method directly because the run() method enforces its own time period
                    firewall_manager_in_verbose_mode.append(enable_firewall._firewall_manager.verbose)
                warn_count_first_reporting_period = warn.call_count

                time.sleep(0.5)  # let 1 reporting period elapse

                for _ in range(0, 5):
                    enable_firewall._operation()
                    firewall_manager_in_verbose_mode.append(enable_firewall._firewall_manager.verbose)

            # Each call to the _operation() method should have checked each rule, and then compared the results of -C against the output of -L
            expected_commands = 10 * [
                mock_iptables.get_accept_dns_command("-C"),
                mock_iptables.get_accept_command("-C"),
                mock_iptables.get_drop_command("-C"),
                "iptables -w -t security -L OUTPUT -nxv"
            ]
            self.assertEqual(expected_commands, mock_iptables.call_list, "Expected commands {0}, got: {1}".format(expected_commands, mock_iptables.call_list))

            #
            # Incorrect firewall settings are reported as warnings, and each reporting period should log these warnings only 3 times. The first reporting period will include an extra warning
            # because the state of the firewall went from "OK" to "not OK" (the initial state is "OK").
            #
            self.assertEqual(4, warn_count_first_reporting_period, "Expected 4 warnings to be logged during the first reporting period, got: {0}".format(warn.call_args_list[:warn_count_first_reporting_period]))
            self.assertEqual(7, len(warn.call_args_list), "Expected a total of 7 warnings to be logged for the two reporting periods, got: {0}".format(warn.call_args_list))
            warnings = get_events_from_mock(warn)
            for w in warnings:
                self.assertTrue(w[0] == "FirewallInconsistency" and w[1].startswith('The results returned by iptables are inconsistent, will not change the current state of the firewall'), "Expected a warning about the results of iptables being inconsistent. Got: {0}".format(w))

            #
            # Once the firewall goes into a "not OK" state, the firewall manager is set to verbose mode in order to make it log the commands it executes. Verbose mode should be set only 3 times
            # per reporting period. The initial state is False, since verbose mode is turned on only after the _operation() method detects an incorrect fire wall state.
            #
            expected_firewall_manager_in_verbose_mode = [False, True, True, True, False, True, True, True, False, False]
            self.assertEqual(expected_firewall_manager_in_verbose_mode, firewall_manager_in_verbose_mode, "The firewall manager is not in verbose mode as expected for each invocation of the firewall operation")

            #
            # The firewall manager logs the commands it executes as info. There should be 6 sets of commands, 3 for each of the 2 reporting periods in the test, plus an initial check for the iptables version
            #
            infos = get_events_from_mock(info)
            expected_commands = ['Using iptables [version 1.4.21] to manage firewall rules'] + \
                6 * [
                    mock_iptables.get_accept_dns_command("-C"),
                    mock_iptables.get_accept_command("-C"),
                    mock_iptables.get_drop_command("-C")
                ]
            for i in range(0, 19):
                self.assertTrue(infos[i][0] == "Firewall" and infos[i][1].startswith(expected_commands[i]), "Expected command '{0}' logged at position {1}. Got: {2}".format(expected_commands[i], i, infos[i]))

            self.assertEqual(0, error.call_count, "No errors should have been reported. Got: {0}". format(error.call_args_list))
    
