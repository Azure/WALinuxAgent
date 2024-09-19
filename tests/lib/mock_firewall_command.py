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
import re

from azurelinuxagent.common.utils import shellutil
from tests.lib.tools import patch

class _MockFirewallCommand(object):
    """
    Abstract base class for the MockIpTables and MockFirewallCmd classes.

    Intercepts calls to shellutil.run_command and mocks the behavior of the firewall command-line utilities using a pre-defined set of return values.
    """
    def __init__(self, command_name, check_option, add_option, delete_option):
        self._command_name = command_name
        self._check_option = check_option
        self._add_option = add_option
        self._delete_option = delete_option
        self._call_list = []
        self._original_run_command = shellutil.run_command
        self._run_command_patcher = patch("azurelinuxagent.ga.firewall_manager.shellutil.run_command", side_effect=self._mock_run_command)
        #
        # Return values for each command-line option (add, check, delete) indexed by rule type (ACCEPT DNS, ACCEPT, DROP, legacy).
        # These default values indicate success, and can be overridden with set_return_values().
        #
        self._return_values = {
            add_option: {
                "ACCEPT DNS": 0,
                "ACCEPT": 0,
                "DROP": 0,
                "legacy": 0,
            },
            check_option: {
                "ACCEPT DNS": 0,
                "ACCEPT": 0,
                "DROP": 0,
                "legacy": 0,
            },
            delete_option: {
                "ACCEPT DNS": 0,
                "ACCEPT": 0,
                "DROP": 0,
                "legacy": 0,
            }
        }

    def __enter__(self):
        self._run_command_patcher.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._run_command_patcher.stop()

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == self._command_name:
            command_string = " ".join(command)
            command = ['sh', '-c', "exit {0}".format(self._get_return_value(command_string))]
            self._call_list.append(command_string)
        return self._original_run_command(command, *args, **kwargs)

    @property
    def check_option(self):
        return self._check_option

    @property
    def add_option(self):
        return self._add_option

    @property
    def delete_option(self):
        return self._delete_option

    @property
    def call_list(self):
        """
        Returns the list of commands that were executed by the mock
        """
        return self._call_list

    def set_return_values(self, option, accept_dns, accept, drop, legacy):
        """
        Changes the return values for the mocked command
        """
        self._return_values[option]["ACCEPT DNS"] = accept_dns
        self._return_values[option]["ACCEPT"] = accept
        self._return_values[option]["DROP"] = drop
        self._return_values[option]["legacy"] = legacy

    def _get_return_value(self, command):
        raise NotImplementedError()

    @staticmethod
    def get_accept_dns_command(option):
        raise NotImplementedError()

    @staticmethod
    def get_accept_command(option):
        raise NotImplementedError()

    @staticmethod
    def get_drop_command(option):
        raise NotImplementedError()

    @staticmethod
    def get_legacy_command(option):
        raise NotImplementedError()


class MockIpTables(_MockFirewallCommand):
    """
    Mock for the iptables command
    """
    def __init__(self, version='1.4.21'):
        super().__init__(command_name="iptables", check_option="-C", add_option="-A", delete_option="-D")
        self._version = version
        # Currently the Agent calls delete repeatedly until it returns 1, indicating that the rule does not exist (and hence the rule has been deleted successfully)
        self.set_return_values("-D", 1, 1, 1, 1)

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == 'iptables' and command[1] == '--version':
            return self._original_run_command(['echo', 'iptables v{0} (nf_tables)'.format(self._version)], *args, **kwargs)
        return super()._mock_run_command(command, *args, **kwargs)

    def _get_return_value(self, command):
        """
        Possible commands are:

            * ACCEPT DNS rule: iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT
            * ACCEPT rule:     iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner <guid> -j ACCEPT
            * DROP rule:       iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP
            * Legacy rule:     iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j ACCEPT

        """
        match = re.match(r"iptables (-w )?-t security (?P<option>-[ACD]) OUTPUT -d 168.63.129.16 -p tcp (?P<rule>--destination-port 53 -j ACCEPT|-m owner --uid-owner \d+ -j ACCEPT|.+ -j (DROP|ACCEPT))", command)
        if match is None:
            raise Exception("Unexpected command: {0}".format(command))
        option = match.group("option")
        rule = match.group("rule")
        if rule == "--destination-port 53 -j ACCEPT":
            return self._return_values[option]["ACCEPT DNS"]
        if rule == "-m owner --uid-owner {0} -j ACCEPT".format(os.getuid()):
            return self._return_values[option]["ACCEPT"]
        if rule == "-m conntrack --ctstate INVALID,NEW -j DROP":
            return self._return_values[option]["DROP"]
        if rule == "-m conntrack --ctstate INVALID,NEW -j ACCEPT":
            return self._return_values[option]["legacy"]
        raise Exception("Unexpected rule: {0}".format(rule))

    @staticmethod
    def get_accept_dns_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT".format(option)

    @staticmethod
    def get_accept_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner {1} -j ACCEPT".format(option, os.getuid())

    @staticmethod
    def get_drop_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP".format(option)

    @staticmethod
    def get_legacy_command(option):
        return "iptables -w -t security {0} OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j ACCEPT".format(option)


class MockFirewallCmd(_MockFirewallCommand):
    """
    Mock for the firewall-cmd command
    """
    def __init__(self):
        super().__init__(command_name="firewall-cmd", check_option="--query-passthrough", add_option="--passthrough", delete_option="--remove-passthrough")

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == 'firewall-cmd' and command[1] == '--state':
            return self._original_run_command(['echo', 'running'], *args, **kwargs)
        return super()._mock_run_command(command, *args, **kwargs)

    def _get_return_value(self, command):
        """
        Possible commands are:

            * ACCEPT DNS rule: firewall-cmd --permanent --direct <--passthrough|--query-passthrough|--remove-passthrough> ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT
            * ACCEPT rule:     firewall-cmd --permanent --direct <--passthrough|--query-passthrough|--remove-passthrough> ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner 0 -j ACCEPT
            * DROP rule:       firewall-cmd --permanent --direct <--passthrough|--query-passthrough|--remove-passthrough> ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP
            * Legacy rule:     firewall-cmd --permanent --direct <--passthrough|--query-passthrough|--remove-passthrough> ipv4 -t security -I OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT

        """
        match = re.match(r"firewall-cmd --permanent --direct (?P<option>--passthrough|--query-passthrough|--remove-passthrough) ipv4 -t security (?P<add_option>-[AI]) OUTPUT -d 168.63.129.16 -p tcp (?P<rule>--destination-port 53 -j ACCEPT|-m owner --uid-owner \d+ -j ACCEPT|.+ -j DROP)", command)
        if match is None:
            raise Exception("Unexpected command: {0}".format(command))
        option = match.group("option")
        rule = match.group("rule")
        add_option = match.group("add_option")
        if rule == "--destination-port 53 -j ACCEPT":
            if add_option == "-I":
                return self._return_values[option]["legacy"]
            return self._return_values[option]["ACCEPT DNS"]
        if rule == "-m owner --uid-owner {0} -j ACCEPT".format(os.getuid()):
            return self._return_values[option]["ACCEPT"]
        if rule == "-m conntrack --ctstate INVALID,NEW -j DROP":
            return self._return_values[option]["DROP"]
        raise Exception("Unexpected rule: {0}".format(rule))

    @staticmethod
    def get_accept_dns_command(option):
        return "firewall-cmd --permanent --direct {0} ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT".format(option)

    @staticmethod
    def get_accept_command(option):
        return "firewall-cmd --permanent --direct {0} ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner {1} -j ACCEPT".format(option, os.getuid())

    @staticmethod
    def get_drop_command(option):
        return "firewall-cmd --permanent --direct {0} ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP".format(option)

    @staticmethod
    def get_legacy_command(option):
        return "firewall-cmd --permanent --direct {0} ipv4 -t security -I OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT".format(option)
