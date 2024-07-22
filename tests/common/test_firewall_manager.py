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
import re
import unittest

from azurelinuxagent.ga.firewall_manager import IpTables
from azurelinuxagent.common.utils import shellutil
from tests.lib.tools import AgentTestCase, patch


@contextlib.contextmanager
def create_mock_iptables(version='1.4.21'):
    # The default return values indicate success; they can be overridden with set_return_values()
    return_values = {
        "-A": {
            "ACCEPT DNS": 0,
            "ACCEPT": 0,
            "DROP": 0,
        },
        "-C": {
            "ACCEPT DNS": 0,
            "ACCEPT": 0,
            "DROP": 0,
        },
        # Note that currently the Agent calls delete repeatedly until it returns 1, indicating that the rule does not exist
        "-D": {
            "ACCEPT DNS": 1,
            "ACCEPT": 1,
            "DROP": 1,
        },
    }

    def set_return_values(option, accept_dns, accept, drop):
        return_values[option]["ACCEPT DNS"] = accept_dns
        return_values[option]["ACCEPT"] = accept
        return_values[option]["DROP"] = drop

    def get_return_value(command):
        """
        Returns the mocked value for the given command, which must be one of the following:

            iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT
            iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner <guid> -j ACCEPT
            iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP

        """
        match = re.match(r"iptables (-w )?-t security (?P<option>-[ACD]) OUTPUT -d 168.63.129.16 -p tcp (?P<rule>--destination-port 53 -j ACCEPT|-m owner --uid-owner \d+ -j ACCEPT|.+ -j DROP)", command)
        if match is None:
            raise Exception("Unexpected command: {0}".format(command))
        option = match.group("option")
        rule = match.group("rule")
        if rule == "--destination-port 53 -j ACCEPT":
            return return_values[option]["ACCEPT DNS"]
        if rule == "-m owner --uid-owner {0} -j ACCEPT".format(os.getuid()):
            return return_values[option]["ACCEPT"]
        if rule == "-m conntrack --ctstate INVALID,NEW -j DROP":
            return return_values[option]["DROP"]
        raise Exception("Unexpected rule: {0}".format(rule))

    original_run_command = shellutil.run_command

    firewall_calls = []

    def mock_run_command(command, *args, **kwargs):
        if command[0] == 'iptables':
            if command[1] == '--version':
                command = ['echo', 'iptables v{0} (nf_tables)'.format(version)]
            else:
                command_string = " ".join(command)
                command = ['sh', '-c', "exit {0}".format(get_return_value(command_string))]
                firewall_calls.append(command_string)

        return original_run_command(command, *args, **kwargs)

    with patch("azurelinuxagent.ga.firewall_manager.shellutil.run_command", side_effect=mock_run_command) as run_command_patcher:
        run_command_patcher.set_return_values = set_return_values
        run_command_patcher.firewall_calls = firewall_calls
        yield run_command_patcher


class TestIpTablesFirewall(AgentTestCase):
    @staticmethod
    def get_accept_dns_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT".format(option)

    @staticmethod
    def get_accept_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner {1} -j ACCEPT".format(option, os.getuid())

    @staticmethod
    def get_drop_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP".format(option)

    def test_setup_should_set_all_the_firewall_rules(self):
        with create_mock_iptables() as mock_iptables:
            firewall = IpTables('168.63.129.16')
            firewall.setup()

            self.assertEqual(
                [
                    self.get_accept_dns_command("-A"),
                    self.get_accept_command("-A"),
                    self.get_drop_command("-A"),
                ],
                mock_iptables.firewall_calls,
                "Expected exactly 3 calls to the -A (append) command")

    def test_remove_should_delete_all_rules(self):
        with create_mock_iptables() as mock_iptables:
            firewall = IpTables('168.63.129.16')
            firewall.remove()

            self.assertEqual(
                [
                    self.get_accept_dns_command("-C"),
                    self.get_accept_command("-C"),
                    self.get_drop_command("-C"),
                    self.get_accept_dns_command("-D"),
                    self.get_accept_command("-D"),
                    self.get_drop_command("-D")
                ],
                mock_iptables.firewall_calls,
                "Expected 3 calls to the -C (check) command, followed by 3 calls to the -D (delete) command")

    def test_remove_should_not_attempt_to_delete_rules_that_do_not_exist(self):
        with create_mock_iptables() as mock_iptables:
            mock_iptables.set_return_values("-C", accept_dns=0, accept=1, drop=0)  # The accept rule does not exist

            firewall = IpTables('168.63.129.16')
            firewall.remove()

            self.assertEqual(
                [
                    self.get_accept_dns_command("-C"),
                    self.get_accept_command("-C"),
                    self.get_drop_command("-C"),
                    self.get_accept_dns_command("-D"),
                    self.get_drop_command("-D"),
                ],
                mock_iptables.firewall_calls,
                "Expected 3 calls to the -C (check) command followed by 2 calls to the -D (delete) command (accept DNS and drop)")

    def test_it_should_not_use_the_wait_option_on_iptables_versions_less_than_1_4_21(self):
        with create_mock_iptables(version='1.4.20') as mock_iptables:
            firewall = IpTables('168.63.129.16')
            firewall.setup()

            self.assertEqual(
                [
                    self.get_accept_dns_command("-A").replace("-w ", ""),
                    self.get_accept_command("-A").replace("-w ", ""),
                    self.get_drop_command("-A").replace("-w ", "")
                ],
                mock_iptables.firewall_calls,
                "Expected only 3 calls to the -A (append) command without the -w option")


if __name__ == '__main__':
    unittest.main()
