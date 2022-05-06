#
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

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError


class RouteEntry(object):
    """
    Represents a single route. The destination, gateway, and mask members are hex representations of the IPv4 address in
    network byte order.
    """

    def __init__(self, interface, destination, gateway, mask, flags, metric):
        self.interface = interface
        self.destination = destination
        self.gateway = gateway
        self.mask = mask
        self.flags = int(flags, 16)
        self.metric = int(metric)

    @staticmethod
    def _net_hex_to_dotted_quad(value):
        if len(value) != 8:
            raise Exception("String to dotted quad conversion must be 8 characters")
        octets = []
        for idx in range(6, -2, -2):
            octets.append(str(int(value[idx:idx + 2], 16)))
        return ".".join(octets)

    def destination_quad(self):
        return self._net_hex_to_dotted_quad(self.destination)

    def gateway_quad(self):
        return self._net_hex_to_dotted_quad(self.gateway)

    def mask_quad(self):
        return self._net_hex_to_dotted_quad(self.mask)

    def to_json(self):
        f = '{{"Iface": "{0}", "Destination": "{1}", "Gateway": "{2}", "Mask": "{3}", "Flags": "{4:#06x}", "Metric": "{5}"}}'
        return f.format(self.interface, self.destination_quad(), self.gateway_quad(), self.mask_quad(),
                        self.flags, self.metric)

    def __str__(self):
        f = "Iface: {0}\tDestination: {1}\tGateway: {2}\tMask: {3}\tFlags: {4:#06x}\tMetric: {5}"
        return f.format(self.interface, self.destination_quad(), self.gateway_quad(), self.mask_quad(),
                        self.flags, self.metric)

    def __repr__(self):
        return 'RouteEntry("{0}", "{1}", "{2}", "{3}", "{4:#04x}", "{5}")' \
            .format(self.interface, self.destination, self.gateway, self.mask, self.flags, self.metric)


class NetworkInterfaceCard:
    def __init__(self, name, link_info):
        self.name = name
        self.ipv4 = set()
        self.ipv6 = set()
        self.link = link_info

    def add_ipv4(self, info):
        self.ipv4.add(info)

    def add_ipv6(self, info):
        self.ipv6.add(info)

    def __eq__(self, other):
        return self.link == other.link and \
               self.ipv4 == other.ipv4 and \
               self.ipv6 == other.ipv6

    @staticmethod
    def _json_array(items):
        return "[{0}]".format(",".join(['"{0}"'.format(x) for x in sorted(items)]))

    def __str__(self):
        entries = ['"name": "{0}"'.format(self.name),
                   '"link": "{0}"'.format(self.link)]
        if len(self.ipv4) > 0:
            entries.append('"ipv4": {0}'.format(self._json_array(self.ipv4)))
        if len(self.ipv6) > 0:
            entries.append('"ipv6": {0}'.format(self._json_array(self.ipv6)))
        return "{{ {0} }}".format(", ".join(entries))


class FirewallCmdDirectCommands(object):
    # firewall-cmd --direct --permanent --passthrough ipv4 -t security -A OUTPUT -d 1.2.3.5 -p tcp -m owner --uid-owner 999 -j ACCEPT
    # success
    # adds the firewalld rule and returns the status
    PassThrough = "--passthrough"

    # firewall-cmd --direct --query-passthrough ipv4 -t security -A OUTPUT -d 1.2.3.5 -p tcp -m owner --uid-owner 9999 -j ACCEPT
    # yes
    # firewall-cmd --direct --permanent --query-passthrough ipv4 -t security -A OUTPUT -d 1.2.3.5 -p tcp -m owner --uid-owner 999 -j ACCEPT
    # no
    # checks if the firewalld rule is present or not
    QueryPassThrough = "--query-passthrough"

    # firewall-cmd --permanent --direct --remove-passthrough ipv4 -t security -A OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner 0 -j ACCEPT
    # success
    # remove the firewalld rule
    RemovePassThrough = "--remove-passthrough"


class AddFirewallRules(object):
    """
    This class is a utility class which is only meant to orchestrate adding Firewall rules (both iptables and firewalld).
    This would also be called from a separate utility binary which would be very early up in the boot order of the VM,
    due to which it would not have access to basic mounts like file-system.
    Please make sure to not log anything in any function this class.
    """

    # -A adds the rule to the end of the iptable chain
    APPEND_COMMAND = "-A"

    # -I inserts the rule at the index specified. If no number specified the rules get added to the top of the chain
    # iptables -t security -I OUTPUT 1 -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT -w and
    # iptables -t security -I OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT -w both adds the rule as the first rule of the chain
    INSERT_COMMAND = "-I"

    # -D deletes the specific rule in the iptable chain
    DELETE_COMMAND = "-D"

    # -C checks if a specific rule exists
    CHECK_COMMAND = "-C"

    @staticmethod
    def __get_iptables_base_command(wait=""):
        """
        If 'wait' is True, adds the wait option (-w) to the given iptables command line
        """
        if wait != "":
            return ["iptables", "-w"]
        return ["iptables"]

    @staticmethod
    def __get_firewalld_base_command(command):
        # For more documentation - https://firewalld.org/documentation/man-pages/firewall-cmd.html
        return ["firewall-cmd", "--permanent", "--direct", command, "ipv4"]

    @staticmethod
    def __get_common_command_params(command, destination):
        return ["-t", "security", command, "OUTPUT", "-d", destination, "-p", "tcp"]

    @staticmethod
    def __get_firewall_base_command(command, destination, firewalld_command="", wait=""):
        # Firewalld.service fails if we set `-w` in the iptables command, so not adding it at all for firewalld commands
        if firewalld_command != "":
            cmd = AddFirewallRules.__get_firewalld_base_command(firewalld_command)
        else:
            cmd = AddFirewallRules.__get_iptables_base_command(wait)
        cmd.extend(AddFirewallRules.__get_common_command_params(command, destination))
        return cmd

    @staticmethod
    def get_accept_tcp_rule(command, destination, firewalld_command="", wait=""):
        # This rule allows DNS TCP request to wireserver ip for non root users
        cmd = AddFirewallRules.__get_firewall_base_command(command, destination, firewalld_command, wait)
        cmd.extend(['--destination-port', '53', '-j', 'ACCEPT'])
        return cmd

    @staticmethod
    def get_wire_root_accept_rule(command, destination, owner_uid, firewalld_command="", wait=""):
        cmd = AddFirewallRules.__get_firewall_base_command(command, destination, firewalld_command, wait)
        cmd.extend(["-m", "owner", "--uid-owner", str(owner_uid), "-j", "ACCEPT"])
        return cmd

    @staticmethod
    def get_wire_non_root_drop_rule(command, destination, firewalld_command="", wait=""):
        cmd = AddFirewallRules.__get_firewall_base_command(command, destination, firewalld_command, wait)
        cmd.extend(["-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "DROP"])
        return cmd

    @staticmethod
    def __raise_if_empty(val, name):
        if val == "":
            raise Exception("{0} should not be empty".format(name))

    @staticmethod
    def __execute_cmd(cmd):
        try:
            shellutil.run_command(cmd)
        except CommandError as error:
            msg = "Command {0} failed with exit-code: {1}\nStdout: {2}\nStderr: {3}".format(' '.join(cmd),
                                                                                            error.returncode,
                                                                                            ustr(error.stdout),
                                                                                            ustr(error.stderr))
            raise Exception(msg)

    @staticmethod
    def __execute_check_command(cmd):
        # Here we primarily check if an  iptable rule exist. True if it exits , false if not
        try:
            shellutil.run_command(cmd)
            return True
        except CommandError as err:
            # return code 1 is expected while using the check command. Raise if encounter any other return code
            if err.returncode != 1:
                raise
        return False

    @staticmethod
    def verify_iptables_rules_exist(wait, dst_ip, uid):
        check_cmd_tcp_rule = AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, dst_ip, wait=wait)
        check_cmd_accept_rule = AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, dst_ip, uid,
                                                                           wait=wait)
        check_cmd_drop_rule = AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, dst_ip, wait=wait)

        return AddFirewallRules.__execute_check_command(check_cmd_tcp_rule) and AddFirewallRules.__execute_check_command(check_cmd_accept_rule) \
               and AddFirewallRules.__execute_check_command(check_cmd_drop_rule)

    @staticmethod
    def __execute_firewall_commands(dst_ip, uid, command=APPEND_COMMAND, firewalld_command="", wait=""):
        # The order in which the below rules are added matters for the ip table rules to work as expected

        AddFirewallRules.__raise_if_empty(dst_ip, "Destination IP")
        AddFirewallRules.__raise_if_empty(uid, "User ID")

        accept_tcp_rule = AddFirewallRules.get_accept_tcp_rule(command, dst_ip,
                                                               firewalld_command=firewalld_command, wait=wait)
        AddFirewallRules.__execute_cmd(accept_tcp_rule)

        accept_cmd = AddFirewallRules.get_wire_root_accept_rule(command, dst_ip, uid,
                                                                firewalld_command=firewalld_command, wait=wait)
        AddFirewallRules.__execute_cmd(accept_cmd)

        drop_cmd = AddFirewallRules.get_wire_non_root_drop_rule(command, dst_ip, firewalld_command=firewalld_command, wait=wait)
        AddFirewallRules.__execute_cmd(drop_cmd)

    @staticmethod
    def add_iptables_rules(wait, dst_ip, uid):
        AddFirewallRules.__execute_firewall_commands(dst_ip, uid, command=AddFirewallRules.APPEND_COMMAND, wait=wait)

    @staticmethod
    def add_firewalld_rules(dst_ip, uid):
        # Firewalld.service fails if we set `-w` in the iptables command, so not adding it at all for firewalld commands
        # Firewalld.service with the "--permanent --passthrough" parameter ensures that a firewall rule is set only once even if command is executed multiple times

        AddFirewallRules.__execute_firewall_commands(dst_ip, uid, firewalld_command=FirewallCmdDirectCommands.PassThrough)

    @staticmethod
    def check_firewalld_rule_applied(dst_ip, uid):
        AddFirewallRules.__execute_firewall_commands(dst_ip, uid, firewalld_command=FirewallCmdDirectCommands.QueryPassThrough)

    @staticmethod
    def remove_firewalld_rules(dst_ip, uid):
        AddFirewallRules.__execute_firewall_commands(dst_ip, uid, firewalld_command=FirewallCmdDirectCommands.RemovePassThrough)
