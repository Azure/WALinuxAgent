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
import contextlib
import os
import unittest

from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.ga.firewall_manager import FirewallManager, IpTables, FirewallCmd, NfTables, FirewallStateError, FirewallManagerNotAvailableError
from tests.lib.tools import AgentTestCase, patch
from tests.lib.mock_firewall_command import MockIpTables, MockFirewallCmd, MockNft


@contextlib.contextmanager
def firewall_command_exists_mock(iptables_exist=True, firewallcmd_exist=True, nft_exists=True):
    """
    Mocks the shellutil.run_command method to fake calls to the iptables/firewall-cmd/nft commands. If ech of those commands should exists,
    the call is faked to return success. Otherwise, the call is faked to invoke a non-existing command.
    """
    commands = {
        "iptables": iptables_exist,
        "firewall-cmd": firewallcmd_exist,
        "nft": nft_exists
    }

    original_run_command = shellutil.run_command

    def mock_run_command(command, *args, **kwargs):
        command_exists = commands.get(command[0])
        if command_exists is not None:
            command = ['sh', '-c', "exit 0"] if command_exists else ["fake-command-that-does-not-exist"]
        return original_run_command(command, *args, **kwargs)

    with patch("azurelinuxagent.ga.firewall_manager.shellutil.run_command", side_effect=mock_run_command) as patcher:
        yield patcher


class TestFirewallManager(AgentTestCase):
    def test_create_should_prefer_iptables_when_both_iptables_and_nftables_exist(self):
        with firewall_command_exists_mock(iptables_exist=True, nft_exists=True):
            firewall = FirewallManager.create('168.63.129.16')
            self.assertIsInstance(firewall, IpTables)

    def test_create_should_use_nftables_when_iptables_does_not_exist(self):
        with firewall_command_exists_mock(iptables_exist=False, nft_exists=True):
            firewall = FirewallManager.create('168.63.129.16')
            self.assertIsInstance(firewall, NfTables)

    def test_create_should_raise_FirewallManagerNotAvailableError_when_both_iptables_and_nftables_do_not_exist(self):
        with firewall_command_exists_mock(iptables_exist=False, nft_exists=False):
            with self.assertRaises(FirewallManagerNotAvailableError):
                FirewallManager.create('168.63.129.16')


class _TestFirewallCommand(AgentTestCase):
    """
    Defines the test cases common to TestIpTables and TestFirewallCmd.

    Note that the test cases are marked as protected to prevent the unit test runner from executing them directly.
    """
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
                    mock.get_accept_dns_command(mock.delete_option),
                    mock.get_accept_command(mock.check_option),
                    mock.get_accept_command(mock.delete_option),
                    mock.get_drop_command(mock.check_option),
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
                    mock.get_accept_dns_command(mock.delete_option),
                    mock.get_accept_command(mock.check_option),
                    mock.get_drop_command(mock.check_option),
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
    def test_it_should_raise_FirewallManagerNotAvailableError_when_the_command_is_not_available(self):
        with firewall_command_exists_mock(iptables_exist=False):
            with self.assertRaises(FirewallManagerNotAvailableError):
                IpTables('168.63.129.16')

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
    def test_it_should_raise_FirewallManagerNotAvailableError_when_the_command_is_not_available(self):
        with firewall_command_exists_mock(firewallcmd_exist=False):
            with self.assertRaises(FirewallManagerNotAvailableError):
                FirewallCmd('168.63.129.16')

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


class TestNft(AgentTestCase):
    def test_it_should_raise_FirewallManagerNotAvailableError_when_the_command_is_not_available(self):
        with firewall_command_exists_mock(nft_exists=False):
            with self.assertRaises(FirewallManagerNotAvailableError):
                NfTables('168.63.129.16')

    def test_setup_should_set_the_walinuxagent_table(self):
        with MockNft() as mock_nft:
            firewall = NfTables('168.63.129.16')
            firewall.setup()

            self.assertEqual(len(mock_nft.call_list), 1, "Expected exactly 1 call to execute a script to create the walinuxagent table; got {0}".format(mock_nft.call_list))

            script = mock_nft.call_list[0]
            self.assertIn("add table ip walinuxagent", script, "The setup script should to create the walinuxagent table. Script: {0}".format(script))
            self.assertIn("add chain ip walinuxagent output", script, "The setup script should to create the output chain. Script: {0}".format(script))
            self.assertIn("add rule ip walinuxagent output ", script, "The setup script should to create the rule to manage the output chain. Script: {0}".format(script))


    def test_remove_should_delete_the_walinuxagent_table(self):
        with MockNft() as mock_nft:
            firewall = NfTables('168.63.129.16')
            firewall.remove()

            self.assertEqual(['nft delete table walinuxagent'], mock_nft.call_list, "Expected a call to delete the walinuxagent table")

    def test_check_should_verify_all_rules(self):
        with MockNft() as mock_nft:
            _, walinuxagent_table = mock_nft.get_return_value(mock_nft.get_list_command("table"))

            firewall = NfTables('168.63.129.16')

            # Remove the clause for DNS and verify check() fails
            stdout = walinuxagent_table.replace('{ "match": {"op": "!=", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": 53}},', '')
            mock_nft.set_return_value("list", "table", (0, stdout))
            with self.assertRaises(FirewallStateError) as context:
                firewall.check()
            self.assertIn("['No expression excludes the DNS port']", str(context.exception), "Expected an error message indicating the DNS port is not excluded")

            # Remove the clause for root and verify check() fails
            stdout = walinuxagent_table.replace('{ "match": {"op": "!=", "left": { "meta": { "key": "skuid" } }, "right": ' + str(os.getuid()) + '}},', '')
            mock_nft.set_return_value("list", "table", (0, stdout))
            with self.assertRaises(FirewallStateError) as context:
                firewall.check()
            self.assertIn('["No expression excludes the Agent\'s UID"]', str(context.exception), "Expected an error message indicating the Agent's UID is not excluded")

            # Remove the "drop" clause and verify check() fails
            stdout = walinuxagent_table.replace('{ "drop": null }', '{ "accept": null }')
            mock_nft.set_return_value("list", "table", (0, stdout))
            with self.assertRaises(FirewallStateError) as context:
                firewall.check()
            self.assertIn("['The drop action is missing']", str(context.exception), "Expected an error message indicating the Agent's UID is not excluded")


if __name__ == '__main__':
    unittest.main()
