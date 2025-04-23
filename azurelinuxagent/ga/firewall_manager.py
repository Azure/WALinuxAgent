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
import errno
import json
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.utils import shellutil

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.shellutil import CommandError


class FirewallManagerNotAvailableError(Exception):
    """
    Exception raised the command-line tool needed to manage the firewall (e.g. iptables, firewalld, nft) is not available
    """


class FirewallStateError(Exception):
    """
    Exception raised when the firewall rules are not set up correctly.
    """


class FirewallManager(object):
    """
    FirewallManager abstracts the interface for managing the firewall rules on the WireServer address. Concrete implementations
    provide the underlying functionality using command-line tools that vary across distros (e.g. iptables, firewalld, and nftables.)
    If a concrete implementation cannot be instantiated because the underlying command-line tool is not available, it must raise
    a FirewallManagerNotAvailable exception.

    Each implementation must set three rules on the WireServer address:

        * "ACCEPT DNS" - Azure DNS runs on the WireServer address, so all traffic on port 53 must be allowed for all users.
        * "ACCEPT"     - All traffic from the Agent (which runs as root) must be accepted.
        * "DROP"       - All other traffic to the WireServer address must be dropped.
    """
    def __init__(self, wire_server_address):
        self._wire_server_address = wire_server_address

    # Friendly names for the firewall rules
    ACCEPT_DNS = "ACCEPT DNS"
    ACCEPT = "ACCEPT"
    DROP = "DROP"

    @staticmethod
    def create(wire_server_address):
        """
        Creates the appropriate FirewallManager implementation depending on the availability of the underlying command-line tools.

        NOTE: Currently this method checks only for iptables and nftables, giving precedence to the former.
        """
        try:
            manager = IpTables(wire_server_address)
            event.info(WALAEventOperation.Firewall, "Using iptables [version {0}] to manage firewall rules", manager.version)
            return manager
        except FirewallManagerNotAvailableError:
            pass

        try:
            manager = NfTables(wire_server_address)
            event.info(WALAEventOperation.Firewall, "Using nft [version {0}] to manage firewall rules", manager.version)
            return manager
        except FirewallManagerNotAvailableError:
            pass

        raise FirewallManagerNotAvailableError("Cannot create a firewall manager; no known command-line tools are available")

    @property
    def version(self):
        """
        Returns the version of the underlying command-line tool.
        """
        raise NotImplementedError()

    def setup(self):
        """
        Sets up the firewall rules for the WireServer.
        """
        raise NotImplementedError()

    def remove(self):
        """
        Removes all the existing firewall rules.
        """
        raise NotImplementedError()

    def remove_legacy_rule(self):
        """
        The iptables and firewalld managers need to remove legacy rules; no-op for other managers.
        """

    def check(self):
        """
        Checks the current state of the firewall.
        Returns True if the firewall is set up correctly, or False if the firewall is not setup.
        Raises a FirewallSetupError if the firewall is only partially set up (e.g. a rule in the chain is missing).

        """
        raise NotImplementedError()

    def get_state(self):
        """
        Returns the current state of the firewall rules as a string. The format of the return value is implementation-specific and depends on the underlying
        command-line tool. If the command to list the rules fails, the return value is an error message.
        """
        try:
            return shellutil.run_command(self._get_state_command())
        except Exception as e:
            message = "Failed to get the current state of the firewall rules: {0}".format(ustr(e))
            logger.warn("Listing firewall rules failed: {0}".format(ustr(e)))
            return message

    def _get_state_command(self):
        """
        Returns the command to list the current state of the firewall.
        """
        raise NotImplementedError()


class _FirewallManagerMultipleRules(FirewallManager):
    """
    Base class for firewall managers that handle multiple rules, each rule being manipulated with a different command line (e.g. iptables, firewalld)
    """
    def setup(self):
        for command in self._get_commands(self._get_append_command_option()):
            shellutil.run_command(command[1])

    def remove(self):
        existing_rules = []

        for rule, command in self._get_commands(self._get_check_command_option()):
            try:
                shellutil.run_command(command)
                existing_rules.append(rule)
            except CommandError as e:
                if e.returncode == 1:  # rule does not exist
                    pass
                else:
                    raise

        for rule, command in self._get_commands(self._get_delete_command_option()):
            if rule in existing_rules:
                self._execute_delete_command(command)

    def remove_legacy_rule(self):
        check_command = self._get_legacy_rule_command(self._get_check_command_option())
        try:
            shellutil.run_command(check_command)
        except CommandError as e:
            if e.returncode == 1:  # rule does not exist
                logger.info("Did not find a legacy firewall rule: {0}", check_command)
                return

        logger.info("Found legacy firewall rule: {0}", check_command)
        delete_command = self._get_legacy_rule_command(self._get_delete_command_option())
        self._execute_delete_command(delete_command)
        event.info(WALAEventOperation.Firewall, "Removed legacy firewall rule: {0}", delete_command)

    def _execute_delete_command(self, command):
        """
        Executes the delete command; derived classes can customize the behavior if needed (for example, to add retries).
        """
        shellutil.run_command(command)

    def check(self):
        missing_rules = []
        existing_rules = []
        missing_rules_reasons = []

        for rule, command in self._get_commands(self._get_check_command_option()):
            try:
                shellutil.run_command(command)
                existing_rules.append(rule)
            except CommandError as e:
                if e.returncode == 1:  # rule does not exist
                    missing_rules.append(rule)
                    # Issue: Even though the drop rule exists, the agent perceives it as missing when checking all rules.
                    # This might occur because we mark the rule as missing due to the same error code being returned for other reasons.
                    # So logging the error message to understand the reason for the rule being marked as missing.
                    missing_rules_reasons.append(e.stderr)
                else:
                    raise

        if len(missing_rules) == 0:  # all rules are present
            return True

        if len(existing_rules) > 0:  # some rules are present, but not all
            raise FirewallStateError("The following rules are missing: {0} due to: {1}".format(missing_rules, missing_rules_reasons))

        return False

    def _get_commands(self, command_option):
        """
        Yields each of the commands needed to set up the firewall rules, using the given command option.

        IMPORTANT: The order in which these rules are returned is critical, since rules are appended sequentially.
                   The first item in the array will be at the top of the chain, etc.
        """
        yield FirewallManager.ACCEPT_DNS, self._get_accept_dns_rule_command(command_option)
        yield FirewallManager.ACCEPT, self._get_accept_rule_command(command_option)
        yield FirewallManager.DROP, self._get_drop_rule_command(command_option)

    def _get_accept_dns_rule_command(self, command_option):
        """
        Returns the command to manipulate the rule for accepting DNS requests on the WireServer address.
        """
        raise NotImplementedError()

    def _get_accept_rule_command(self, command_option):
        """
        Returns the command to manipulate the rule for accepting request on the WireServer address issued by the Agent.
        """
        raise NotImplementedError()

    def _get_drop_rule_command(self, command_option):
        """
        Returns the command to manipulate the rule for dropping all requests on the WireServer address.
        """
        raise NotImplementedError()

    def _get_legacy_rule_command(self, command_option):
        """
        Returns the command to delete the legacy firewall rule.

        See the overrides of this method for details on those rules.
        """
        raise NotImplementedError()

    def _get_append_command_option(self):
        """
        Returns the command-line option to append a firewall to the output chain.
        """
        raise NotImplementedError()

    def _get_check_command_option(self):
        """
        Returns the command-line option to check for existence of rule on the output chain.
        """
        raise NotImplementedError()

    def _get_delete_command_option(self):
        """
        Returns the command-line option to delete a firewall rule from the output chain.
        """
        raise NotImplementedError()


class IpTables(_FirewallManagerMultipleRules):
    """
    FirewallManager based on the iptables command-line tool.
    """
    def __init__(self, wire_server_address):
        super(IpTables, self).__init__(wire_server_address)

        #
        # The wait option, "-w" was introduced in iptables 1.4.21. Check if we can use it.
        #
        try:
            output = shellutil.run_command(["iptables", "--version"])
            #
            # The output is similar to
            #
            #     $ iptables --version
            #     iptables v1.8.7 (nf_tables)
            #
            # Extract anything that looks like a version number.
            #
            match = re.match(r"^[^\d.]*([\d.]+).*$", output)
            if match is None:
                raise Exception('output of "--version": {0}'.format(output))
            self._version = FlexibleVersion(match.group(1))
            use_wait_option = self._version >= FlexibleVersion('1.4.21')

        except Exception as exception:
            if isinstance(exception, OSError) and exception.errno == errno.ENOENT:  # pylint: disable=no-member
                raise FirewallManagerNotAvailableError("iptables is not available")
            event.warn(WALAEventOperation.Firewall, "Unable to determine version of iptables; will not use -w option. --version output: {0}", ustr(exception))
            self._version = "unknown"
            use_wait_option = False

        if use_wait_option:
            self._base_command = ["iptables", "-w", "-t", "security"]
        else:
            self._base_command = ["iptables", "-t", "security"]

    @property
    def version(self):
        return self._version

    def _execute_delete_command(self, command):
        """
        Continually execute the delete operation until the return code is non-zero or the limit has been reached.
        """
        for _ in range(1, 100):
            try:
                shellutil.run_command(command)
            except CommandError as e:
                if e.returncode == 1:
                    return
                if e.returncode == 2:
                    raise Exception("Invalid firewall deletion command '{0}'".format(command))

    def _get_state_command(self):
        return self._base_command + ["-t", "security", "-L", "-nxv"]

    def _get_accept_dns_rule_command(self, command_option):
        return self._base_command + [command_option, "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "--destination-port", "53", "-j", "ACCEPT"]

    def _get_accept_rule_command(self, command_option):
        return self._base_command + [command_option, "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "-m", "owner", "--uid-owner", str(os.getuid()), "-j", "ACCEPT"]

    def _get_drop_rule_command(self, command_option):
        return self._base_command + [command_option, "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "DROP"]

    def _get_legacy_rule_command(self, command_option):
        # There was a rule change at 2.2.26, which started dropping non-root traffic to WireServer. The previous rule allowed traffic, and needs to be removed
        # for the newer DROP rule to have any effect. This function returns the command to manipulate the legacy rule that was added <= 2.2.25. Until 2.2.25
        # has aged out, keep this cleanup in place.
        return self._base_command + [command_option, "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "ACCEPT"]

    def _get_append_command_option(self):
        return "-A"

    def _get_check_command_option(self):
        return "-C"

    def _get_delete_command_option(self):
        return "-D"


class FirewallCmd(_FirewallManagerMultipleRules):
    """
    FirewallManager based on the firewalld command-line tool.
    """
    def __init__(self, wire_server_address):
        super(FirewallCmd, self).__init__(wire_server_address)

        try:
            self._version = shellutil.run_command(["firewall-cmd", "--version"]).strip()
        except Exception as exception:
            if isinstance(exception, OSError) and exception.errno == errno.ENOENT:  # pylint: disable=no-member
                raise FirewallManagerNotAvailableError("nft is not available")
            self._version = "unknown"

    @property
    def version(self):
        return self._version

    def _get_state_command(self):
        return ["firewall-cmd", "--permanent", "--direct", "--get-all-passthroughs"]

    def _get_accept_dns_rule_command(self, command_option):
        return ["firewall-cmd", "--permanent", "--direct", command_option, "ipv4", "-t", "security", "-A", "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", '--destination-port', '53', '-j', 'ACCEPT']

    def _get_accept_rule_command(self, command_option):
        return ["firewall-cmd", "--permanent", "--direct", command_option, "ipv4", "-t", "security", "-A", "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "-m", "owner", "--uid-owner", str(os.getuid()), "-j", "ACCEPT"]

    def _get_drop_rule_command(self, command_option):
        return ["firewall-cmd", "--permanent", "--direct", command_option, "ipv4", "-t", "security", "-A", "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "DROP"]

    def _get_legacy_rule_command(self, command_option):
        # Agents <= 2.7.0.6 inserted (-I) the rule to accept DNS traffic; later agents changed that to append (-A) the rule.
        # The insert rule needs to be removed, otherwise there will be duplicate rules for DNS.
        return ["firewall-cmd", "--permanent", "--direct", command_option, "ipv4", "-t", "security", "-I", "OUTPUT", "-d", self._wire_server_address, "-p", "tcp", '--destination-port', '53', '-j', 'ACCEPT']

    def _get_append_command_option(self):
        return "--passthrough"

    def _get_check_command_option(self):
        return "--query-passthrough"

    def _get_delete_command_option(self):
        return "--remove-passthrough"


class NfTables(FirewallManager):
    """
    FirewallManager based on the nft command-line tool.
    """
    def __init__(self, wire_server_address):
        super(NfTables, self).__init__(wire_server_address)

        try:
            self._version = shellutil.run_command(["nft", "--version"]).strip()
        except Exception as exception:
            if isinstance(exception, OSError) and exception.errno == errno.ENOENT:  # pylint: disable=no-member
                raise FirewallManagerNotAvailableError("nft is not available")
            self._version = "unknown"

    @property
    def version(self):
        return self._version

    def setup(self):
        shellutil.run_command(["nft", "-f", "-"], input="""
            add table ip walinuxagent
            add chain ip walinuxagent output {{ type filter hook output priority 0 ; policy accept ; }}
            add rule ip walinuxagent output ip daddr {0} tcp dport != 53 skuid != {1} ct state invalid,new counter drop
        """.format(self._wire_server_address, os.getuid()))

    def remove(self):
        shellutil.run_command(["nft", "delete", "table", "walinuxagent"])

    def check(self):
        #
        # First check that the walinuxagent table exists.
        #
        # The output of the list command is similar to (see 'man libnftables-json' for details):
        #
        #   {
        #     "nftables": [
        #         { "metainfo": { "version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1 } },
        #         { "table": { "family": "ip", "name": "walinuxagent", "handle": 2 } }
        #     ]
        #   }
        #
        output_text = shellutil.run_command(["nft", "--json",  "list", "tables"])
        try:
            output = json.loads(output_text)
            tables = [i["table"] for i in output["nftables"] if i.get("table") is not None]
            if all(t["name"] != "walinuxagent" for t in tables):
                return False
        except Exception as exception:
            raise Exception("Can't parse the output of 'nft list tables'\n{0}\nERROR: {1}".format(output_text, exception))

        #
        # Now check that the firewall rule is set up correctly.
        #
        # The output of the list command is similar to (see 'man libnftables-json' for details):
        #
        #   {
        #     "nftables": [
        #       { "metainfo": { "version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1 } },
        #       { "table": { "family": "ip", "name": "walinuxagent", "handle": 2 } },
        #       { "chain": { "family": "ip", "table": "walinuxagent", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept" } },
        #       {
        #         "rule": {
        #           "family": "ip", "table": "walinuxagent", "chain": "output", "handle": 2,
        #           "expr": [
        #             { "match": {
        #                 "op": "==",
        #                 "left": {  "payload": { "protocol": "ip", "field": "daddr" } },
        #                 "right": "168.63.129.16"
        #               }},
        #             { "match": {
        #                 "op": "!=",
        #                 "left": { "payload": { "protocol": "tcp", "field": "dport" } },
        #                 "right": 53
        #               }},
        #             { "match": {
        #                 "op": "!=",
        #                 "left": { "meta": { "key": "skuid" } },
        #                 "right": 0
        #               }},
        #             { "match": {
        #                 "op": "in",
        #                 "left": { "ct": { "key": "state" } },
        #                 "right": [ "invalid", "new" ]
        #               }},
        #             { "counter": {
        #                 "packets": 0,
        #                 "bytes": 0
        #               }},
        #             { "drop": null }
        #          ]
        #         }
        #       }
        #     ]
        #   }
        #
        output_text = shellutil.run_command(["nft", "--json",  "list", "table", "walinuxagent"])
        errors = []

        try:
            output = json.loads(output_text)

            rules = [i["rule"] for i in output["nftables"] if i.get("rule") is not None]
            if len(rules) != 1:
                raise FirewallStateError("There should be exactly one rule in the 'output' chain")
            for r in rules:
                if r["table"] == "walinuxagent" and r["family"] == "ip" and r["chain"] == "output":
                    expr = r["expr"]
                    break
            else:
                raise FirewallStateError("Cannot find any rules for the 'output' chain")

            address_match = {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": self._wire_server_address}}
            if all(i != address_match for i in expr):
                errors.append("No expression matches the WireServer address")

            dns_match = {"match": {"op": "!=", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 53}}
            if all(i != dns_match for i in expr):
                errors.append("No expression excludes the DNS port")

            owner_expr = {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": os.getuid()}}
            if all(i != owner_expr for i in expr):
                errors.append("No expression excludes the Agent's UID")

            drop_action = {"drop": None}
            if all(i != drop_action for i in expr):
                errors.append("The drop action is missing")

        except FirewallStateError:
            raise
        except Exception as exception:
            raise Exception("Can't parse the output of 'nft list table walinuxagent'\n{0}\nERROR: {1}".format(output_text, exception))

        if len(errors) > 0:
            raise FirewallStateError("{0}".format(errors))

        return True

    def _get_state_command(self):
        return ['nft', 'list', 'table', 'walinuxagent']





