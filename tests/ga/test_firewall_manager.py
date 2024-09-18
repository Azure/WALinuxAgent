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
import unittest

from azurelinuxagent.ga.firewall_manager import IpTables, FirewallCmd
from tests.lib.tools import AgentTestCase
from tests.lib.mock_firewall_command import MockIpTables, MockFirewallCmd

class _TestFirewallCommand(AgentTestCase):
    def _test_setup_should_set_all_the_firewall_rules(self, firewall_cmd_type, mock_firewall_cmd_type):
        with mock_firewall_cmd_type() as mock:
            firewall = firewall_cmd_type('168.63.129.16')
            firewall.setup()

            self.assertEqual(
                [
                    mock.get_accept_dns_command(mock.add_option),
                    mock.get_accept_command(mock.add_option),
                    mock.get_drop_command(mock.add_option),
                ],
                mock.call_list,
                "Expected exactly 3 calls to the {0} (add) command".format(mock.add_option))

    def _test_remove_should_delete_all_rules(self, firewall_cmd_type, mock_firewall_cmd_type):
        with mock_firewall_cmd_type() as mock:
            firewall = firewall_cmd_type('168.63.129.16')
            firewall.remove()

            self.assertEqual(
                [
                    mock.get_accept_dns_command(mock.check_option),
                    mock.get_accept_command(mock.check_option),
                    mock.get_drop_command(mock.check_option),
                    mock.get_accept_dns_command(mock.delete_option),
                    mock.get_accept_command(mock.delete_option),
                    mock.get_drop_command(mock.delete_option)
                ],
                mock.call_list,
                "Expected 3 calls to the {0} (check) command, followed by 3 calls to the {1} (delete) command".format(mock.add_option, mock.delete_option))

    def _test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(self, firewall_cmd_type, mock_firewall_cmd_type):
        with mock_firewall_cmd_type() as mock:
            mock.set_return_values(mock.check_option, accept_dns=0, accept=1, drop=0, legacy=0)  # The accept rule does not exist

            firewall = firewall_cmd_type('168.63.129.16')
            firewall.remove()

            self.assertEqual(
                [
                    mock.get_accept_dns_command(mock.check_option),
                    mock.get_accept_command(mock.check_option),
                    mock.get_drop_command(mock.check_option),
                    mock.get_accept_dns_command(mock.delete_option),
                    mock.get_drop_command(mock.delete_option),
                ],
                mock.call_list,
                "Expected 3 calls to the {0} (check) command followed by 2 calls to the {1} (delete) command (accept DNS and drop)".format(mock.check_option, mock.delete_option))

    def _test_check_should_verify_all_rules(self, firewall_cmd_type, mock_firewall_cmd_type):
        with mock_firewall_cmd_type() as mock:
            firewall = firewall_cmd_type('168.63.129.16')
            firewall.check()

            self.assertEqual(
                [
                    mock.get_accept_dns_command(mock.check_option),
                    mock.get_accept_command(mock.check_option),
                    mock.get_drop_command(mock.check_option)
                ],
                mock.call_list,
                "Expected 3 calls to the {0} (check) command".format(mock.check_option))

    def _test_remove_legacy_rule_should_delete_the_legacy_rule(self, firewall_cmd_type, mock_firewall_cmd_type):
        with mock_firewall_cmd_type() as mock:
            firewall = firewall_cmd_type('168.63.129.16')
            firewall.remove_legacy_rule()

            self.assertEqual(
                [
                    mock.get_legacy_command(mock.check_option),
                    mock.get_legacy_command(mock.delete_option)
                ],
                mock.call_list,
                "Expected a check ({0}) for the legacy rule, followed by a delete ({1}) of the rule".format(mock.check_option, mock.delete_option))


class TestIpTables(_TestFirewallCommand):
    def test_setup_should_set_all_the_firewall_rules(self):
        self._test_setup_should_set_all_the_firewall_rules(IpTables, MockIpTables)

    def test_remove_should_delete_all_rules(self):
        self._test_remove_should_delete_all_rules(IpTables, MockIpTables)

    def test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(self):
        self._test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(IpTables, MockIpTables)

    def test_check_should_verify_all_rules(self):
        self._test_check_should_verify_all_rules(IpTables, MockIpTables)

    def test_remove_legacy_rule_should_delete_the_legacy_rule(self):
        self._test_remove_legacy_rule_should_delete_the_legacy_rule(IpTables, MockIpTables)

    def test_it_should_not_use_the_wait_option_on_iptables_versions_less_than_1_4_21(self):
        with MockIpTables(version='1.4.20') as mock_iptables:
            firewall = IpTables('168.63.129.16')
            firewall.setup()

            self.assertEqual(
                [
                    MockIpTables.get_accept_dns_command("-A").replace("-w ", ""),
                    MockIpTables.get_accept_command("-A").replace("-w ", ""),
                    MockIpTables.get_drop_command("-A").replace("-w ", "")
                ],
                mock_iptables.call_list,
                "Expected only 3 calls to the -A (append) command without the -w option")


class TestFirewallCmd(_TestFirewallCommand):
    def test_setup_should_set_all_the_firewall_rules(self):
        self._test_setup_should_set_all_the_firewall_rules(FirewallCmd, MockFirewallCmd)

    def test_remove_should_delete_all_rules(self):
        self._test_remove_should_delete_all_rules(FirewallCmd, MockFirewallCmd)

    def test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(self):
        self._test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(FirewallCmd, MockFirewallCmd)

    def test_check_should_verify_all_rules(self):
        self._test_check_should_verify_all_rules(FirewallCmd, MockFirewallCmd)

    def test_remove_legacy_rule_should_delete_the_legacy_rule(self):
        self._test_remove_legacy_rule_should_delete_the_legacy_rule(FirewallCmd, MockFirewallCmd)


if __name__ == '__main__':
    unittest.main()
