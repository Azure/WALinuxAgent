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
            self._call_list.append(command_string)
            exit_code, stdout, stderr = self._get_return_value(command_string)
            if exit_code != 0:
                raise shellutil.CommandError(command=command_string, return_code=exit_code, stdout=stdout, stderr=stderr)
            return stdout
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
    def __init__(self, version='1.4.21', check_matches_list=True):
        super(MockIpTables, self).__init__(command_name="iptables", check_option="-C", add_option="-A", delete_option="-D")
        self._version = version
        # Currently the Agent calls delete repeatedly until it returns 1, indicating that the rule does not exist (and hence the rule has been deleted successfully)
        self.set_return_values("-D", 1, 1, 1, 1)
        self._check_matches_list = check_matches_list

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == 'iptables' and command[1] == '--version':
            return self._original_run_command(['echo', 'iptables v{0} (nf_tables)'.format(self._version)], *args, **kwargs)
        return super(MockIpTables, self)._mock_run_command(command, *args, **kwargs)

    def _get_return_value(self, command):
        """
        Possible commands are:

            * ACCEPT DNS rule: iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT
            * ACCEPT rule:     iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner <guid> -j ACCEPT
            * DROP rule:       iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP
            * Legacy rule:     iptables [-w] -t security <-A|-C|-D> OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j ACCEPT

        """
        match = re.match(r"iptables (-w )?-t security (?P<option>-[ACD]) OUTPUT -d 168.63.129.16 -p tcp (?P<rule>--destination-port 53 -j ACCEPT|-m owner --uid-owner \d+ -j ACCEPT|.+ -j (DROP|ACCEPT))", command)
        if match is not None:
            option = match.group("option")
            rule = match.group("rule")
            if rule == "--destination-port 53 -j ACCEPT":
                exit_code = self._return_values[option]["ACCEPT DNS"]
            elif rule == "-m owner --uid-owner {0} -j ACCEPT".format(os.getuid()):
                exit_code = self._return_values[option]["ACCEPT"]
            elif rule == "-m conntrack --ctstate INVALID,NEW -j DROP":
                exit_code = self._return_values[option]["DROP"]
            elif rule == "-m conntrack --ctstate INVALID,NEW -j ACCEPT":
                exit_code = self._return_values[option]["legacy"]
            else:
                raise Exception("Unexpected rule: {0}".format(rule))
            return exit_code, "Mocked stdout", "Mocked stderr"

        match = re.match(r"iptables (-w )?-t security -L (?P<output>OUTPUT )?-nxv", command)
        if match is not None:
            #
            # Create the mock output for iptables -L
            #
            #     # iptables -w -t security -L OUTPUT -nvx
            #     Chain OUTPUT (policy ACCEPT 1384 packets, 126406 bytes)
            #         pkts      bytes target     prot opt in     out     source               destination
            #            0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        tcp dpt:53
            #            0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        owner UID match 0
            #            0        0 DROP       tcp  --  *      *       0.0.0.0/0            168.63.129.16        ctstate INVALID,NEW
            #
            #     # iptables -w -t security -L -nvx
            #     Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
            #         pkts      bytes target     prot opt in     out     source               destination
            #
            #     Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
            #         pkts      bytes target     prot opt in     out     source               destination
            #
            #     Chain OUTPUT (policy ACCEPT 1384 packets, 126406 bytes)
            #         pkts      bytes target     prot opt in     out     source               destination
            #            0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        tcp dpt:53
            #            0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        owner UID match 0
            #            0        0 DROP       tcp  --  *      *       0.0.0.0/0            168.63.129.16        ctstate INVALID,NEW
            #
            #
            if match.group("output") is not None:
                stdout = [
                    "Chain OUTPUT (policy ACCEPT 1384 packets, 126406 bytes)\n",
                    "    pkts      bytes target     prot opt in     out     source               destination\n"
                ]
            else:
                stdout = [
                    "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n",
                    "    pkts      bytes target     prot opt in     out     source               destination\n",
                    "\n",
                    "Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)\n",
                    "    pkts      bytes target     prot opt in     out     source               destination\n",
                    "\n",
                    "Chain OUTPUT (policy ACCEPT 1384 packets, 126406 bytes)\n",
                    "    pkts      bytes target     prot opt in     out     source               destination\n"
                ]
            if (self._return_values["-C"]["ACCEPT DNS"] == 0) == self._check_matches_list:
                stdout.append("       0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        tcp dpt:53\n")
            if (self._return_values["-C"]["ACCEPT"] == 0) == self._check_matches_list:
                stdout.append("       0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            168.63.129.16        owner UID match 0\n")
            if (self._return_values["-C"]["DROP"] == 0) == self._check_matches_list:
                stdout.append("       0        0 DROP       tcp  --  *      *       0.0.0.0/0            168.63.129.16        ctstate INVALID,NEW\n")
            return 0, "".join(stdout), ""

        raise Exception("Unexpected command: {0}".format(command))

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

    @staticmethod
    def get_list_command():
        return "iptables -w -t security -L -nxv"


class MockFirewallCmd(_MockFirewallCommand):
    """
    Mock for the firewall-cmd command
    """
    def __init__(self):
        super(MockFirewallCmd, self).__init__(command_name="firewall-cmd", check_option="--query-passthrough", add_option="--passthrough", delete_option="--remove-passthrough")

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == 'firewall-cmd' and command[1] == '--version':
            return '1.0.0 (mocked)'
        if command[0] == 'firewall-cmd' and command[1] == '--state':
            return 'running\n'
        return super(MockFirewallCmd, self)._mock_run_command(command, *args, **kwargs)

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
            exit_code = self._return_values[option]["legacy"] if add_option == "-I" else self._return_values[option]["ACCEPT DNS"]
        elif rule == "-m owner --uid-owner {0} -j ACCEPT".format(os.getuid()):
            exit_code = self._return_values[option]["ACCEPT"]
        elif rule == "-m conntrack --ctstate INVALID,NEW -j DROP":
            exit_code = self._return_values[option]["DROP"]
        else:
            raise Exception("Unexpected rule: {0}".format(rule))

        return exit_code, "Mocked stdout", "Mocked stderr"

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

    @staticmethod
    def get_list_command():
        return "firewall-cmd --permanent --direct --get-all-passthroughs"


class MockNft(object):
    """
    Intercepts calls to shellutil.run_command and mocks the behavior of the nft command-line utility using a pre-defined set of return values.
    """
    def __init__(self):
        self._call_list = []
        self._original_run_command = shellutil.run_command
        self._run_command_patcher = patch("azurelinuxagent.ga.firewall_manager.shellutil.run_command", side_effect=self._mock_run_command)
        #
        # Return values for the "delete" and "list" options of the nft command. Each item is a (exit_code, stdout) tuple.
        # The default values below indicate success, and can be overridden with  the set_return_value() method.
        #
        self._return_values = {
            "delete": {
                "table": (0, ''),  # nft delete table walinuxagent
            },
            "list": {
                "tables": (0,   # nft --json list tables
'''
{
  "nftables": [
      { "metainfo": { "version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1 } },
      { "table": { "family": "ip", "name": "walinuxagent", "handle": 2 } }
  ]
}
'''),
                "table": (0,  # nft --json  list table walinuxagent
'''
 {
  "nftables": [
    { "metainfo": { "version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1 } },
    { "table": { "family": "ip", "name": "walinuxagent", "handle": 2 } },
    { "chain": { "family": "ip", "table": "walinuxagent", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept" } },
    {
      "rule": {
        "family": "ip", "table": "walinuxagent", "chain": "output", "handle": 2,
        "expr": [
          { "match": {"op": "==", "left": {  "payload": { "protocol": "ip", "field": "daddr" } }, "right": "168.63.129.16"}},
          { "match": {"op": "!=", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": 53}},
          { "match": {"op": "!=", "left": { "meta": { "key": "skuid" } }, "right": ''' + str(os.getuid()) +'''}},
          { "match": {"op": "in", "left": { "ct": { "key": "state" } }, "right": [ "invalid", "new" ]}},
          { "counter": {"packets": 0, "bytes": 0}},
          { "drop": null }
       ]
      }
    }
  ]
}
''')
            }
        }

    def __enter__(self):
        self._run_command_patcher.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._run_command_patcher.stop()

    def _mock_run_command(self, command, *args, **kwargs):
        if command[0] == 'nft':
            command_string = " ".join(command)
            if command_string == "nft --version":
                # return a hardcoded version string and don't add the command to the call list
                return self._original_run_command(['echo', 'nftables v1.0.2 (Lester Gooch)'], *args, **kwargs)
            elif command_string == 'nft -f -':
                # if we are executing an nft script, add the script to the call list and return success with no stdout (empty string)
                script = self._original_run_command(['cat'], *args, **kwargs)
                self._call_list.append(script)
                return self._original_run_command(['echo', '-n'], *args, **kwargs)
            # get the exit code and stdout from the pre-defined table of return values and add the command to the call list
            exit_code, stdout = self.get_return_value(command_string)
            command = ['sh', '-c', "echo '{0}'; exit {1}".format(stdout, exit_code)]
            self._call_list.append(command_string)
        return self._original_run_command(command, *args, **kwargs)

    @property
    def call_list(self):
        """
        Returns the list of commands that were executed by the mock
        """
        return self._call_list

    def set_return_value(self, command, target, return_value):
        """
        Changes the return values for the mocked command
        """
        if command not in self._return_values or target not in self._return_values[command]:
            raise Exception("Unexpected command: {0} {1}".format(command, target))
        self._return_values[command][target] = return_value

    def get_return_value(self, command):
        """
        Possible commands are:

            nft delete table walinuxagent
            nft --json list tables
            nft --json  list table walinuxagent
        """
        if command == "nft delete table walinuxagent":
            return self._return_values["delete"]["table"]
        match = re.match(r"nft --json list (?P<target>tables|table)( walinuxagent)?", command)
        if match is not None:
            target = match.group("target")
            return self._return_values["list"][target]
        raise Exception("Unexpected command: {0}".format(command))

    @staticmethod
    def get_list_command(target):
        if target == "tables":
            return "nft --json list tables"
        if target == "table":
            return "nft --json list table walinuxagent"
        raise Exception("Unexpected command target: {0}".format(target))
