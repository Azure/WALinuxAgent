#!/usr/bin/env pypy3

# Microsoft Azure Linux Agent
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

import errno
import json
import re
import time

from assertpy import fail
from typing import Callable, Dict, List

from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from tests_e2e.tests.lib.logging import log


def get_wireserver_ip() -> str:
    try:
        with open('/var/lib/waagent/WireServerEndpoint', 'r') as f:
            wireserver_ip = f.read()
    except:  # pylint: disable=bare-except
        wireserver_ip = '168.63.129.16'
    return wireserver_ip


class FirewallConfigurationError(Exception):
    """
    Exception raised when the firewall is not configured correctly
    """


class FirewallManager:
    """
    Utilities to manage the firewall
    """

    def __init__(self):
        self._wire_server_address = get_wireserver_ip()

    FIREWALL_PERIOD = 30

    ACCEPT_DNS = "ACCEPT DNS"
    ACCEPT = "ACCEPT"
    DROP = "DROP"

    @staticmethod
    def create():
        """
        Creates the appropriate firewall manager to 
        """
        try:
            shellutil.run_command(["sudo", "iptables", "--version"])  # On some distros, e.g. CentOS, iptables is not on the PATH for regular users
            log.info("Using iptables to manage the firewall")
            return IpTables()
        except CommandError:
            pass

        try:
            shellutil.run_command(["nft", "--version"])
            log.info("Using nftables to manage the firewall")
            return NfTables()
        except FileNotFoundError:
            pass

        raise Exception("No firewall commands are installed")

    def get_state(self) -> str:
        raise NotImplementedError()

    def get_missing_rules(self) -> List[str]:
        raise NotImplementedError()

    def check_rule(self, rule_name: str) -> bool:
        raise NotImplementedError()

    def delete_rule(self, rule_name: str) -> None:
        raise NotImplementedError()

    def log_firewall_state(self, header: str) -> None:
        try:
            log.info(f"{header}:\n{self.get_state()}")
        except Exception as error:
            log.warning(f"Error -- Failed to get the current state of the firewall: {error}")

    def assert_all_rules_are_set(self) -> None:
        """
        Fails the test if any of the firewall rules are missing
        """
        log.info("Verifying all firewall rules are set...")
        # Agent will re-add rules within OS.EnableFirewallPeriod, So waiting that time + some buffer
        missing = self.get_missing_rules()
        if len(missing) > 0:
            log.info("Some firewall rules are missing. Waiting for a short period to give the agent a chance to re-add the rules...")
            time.sleep(self.FIREWALL_PERIOD + 15)
            missing = self.get_missing_rules()

        if len(missing) > 0:
            fail(f"Some firewall rules are missing: {missing}. Current firewall rules:\n{self.get_state()}")

        log.info("All firewall rules are set")

    def verify_rule_is_not_set(self, rule_name: str) -> None:
        """
        This function verifies that the given rule is not set (for example, if it was just deleted).
        """
        log.info(f"-----Verifying firewall rule {rule_name} is not set")

        if self.check_rule(rule_name):
            raise Exception(f"Firewall rule {rule_name} should not be set. Current firewall state:\n{self.get_state()}")

        log.info(f"Firewall rule {rule_name} is not set")

    @staticmethod
    def _log_and_run_command(command: str) -> str:
        log.info(f"Executing command: {command}")
        return shellutil.run_command(command.split(" "))


class _IpTablesFirewalldManager(FirewallManager):
    """
    Base class for the IpTables and Firewalld classes
    """

    def __init__(self):
        super().__init__()
        self._commands: Dict[str, Callable] = {
            self.ACCEPT_DNS: self._get_accept_dns_command,
            self.ACCEPT: self._get_accept_command,
            self.DROP: self._get_accept_drop_command
        }

    def get_state(self) -> str:
        return self._log_and_run_command(self._get_state_command())

    def get_missing_rules(self) -> List[str]:
        missing = []

        for name, get_command in self._commands.items():
            try:
                command_option = self._get_check_command_option()
                self._log_and_run_command(get_command(command_option))
            except CommandError as command_error:
                if command_error.returncode != 1:
                    raise
                missing.append(name)

        return missing

    def check_rule(self, rule_name: str) -> bool:
        try:
            command_option = self._get_check_command_option()
            self._log_and_run_command(self._commands[rule_name](command_option))
        except CommandError as command_error:
            if command_error.returncode == 1:
                return False
            raise
        return True

    def delete_rule(self, rule_name: str) -> None:
        command_option = self._get_delete_command_option()
        self._log_and_run_command(self._commands[rule_name](command_option))

    def _get_state_command(self) -> str:
        raise NotImplementedError()

    def _get_check_command_option(self) -> str:
        raise NotImplementedError()

    def _get_delete_command_option(self) -> str:
        raise NotImplementedError()

    def _get_accept_dns_command(self, command_option: str) -> str:
        raise NotImplementedError()

    def _get_accept_command(self, command_option: str) -> str:
        raise NotImplementedError()

    def _get_accept_drop_command(self, command_option: str) -> str:
        raise NotImplementedError()


class IpTables(_IpTablesFirewalldManager):
    """
    Implementation of Firewall using the iptables command
    """

    def _get_state_command(self) -> str:
        return "sudo iptables -w -t security -L -nxv"

    def _get_check_command_option(self) -> str:
        return "-C"

    def _get_delete_command_option(self) -> str:
        return "-D"

    def _get_accept_dns_command(self, command_option: str) -> str:
        return f"sudo iptables -w -t security {command_option} OUTPUT -d {self._wire_server_address} -p tcp --destination-port 53 -j ACCEPT"

    def _get_accept_command(self, command_option: str) -> str:
        return f"sudo iptables -w -t security {command_option} OUTPUT -d {self._wire_server_address} -p tcp -m owner --uid-owner 0 -j ACCEPT"

    def _get_accept_drop_command(self, command_option: str) -> str:
        return f"sudo iptables -w -t security {command_option} OUTPUT -d {self._wire_server_address} -p tcp -m conntrack --ctstate INVALID,NEW -j DROP"


class Firewalld(_IpTablesFirewalldManager):
    """
    Implementation of Firewall using the firewall-cmd command
    """

    @staticmethod
    def is_service_running() -> bool:
        """
        Returns true if the firewalld service is running on the VM
        """
        try:
            return shellutil.run_command(["firewall-cmd", "--state"]).rstrip() == "running"
        except Exception as exception:
            if isinstance(exception, OSError) and exception.errno == errno.ENOENT:  # pylint: disable=no-member
                return False
            log.info(f"The firewalld service is present, but it is not running: {exception}")
            return False

    def _get_state_command(self) -> str:
        return "sudo firewall-cmd --permanent --direct --get-all-passthroughs"

    def _get_check_command_option(self) -> str:
        return "--query-passthrough"

    def _get_delete_command_option(self) -> str:
        return "--remove-passthrough"

    def _get_accept_dns_command(self, command_option: str) -> str:
        return f"firewall-cmd --permanent --direct {command_option} ipv4 -t security -A OUTPUT -d {self._wire_server_address} -p tcp --destination-port 53 -j ACCEPT"

    def _get_accept_command(self, command_option: str) -> str:
        return f"firewall-cmd --permanent --direct {command_option} ipv4 -t security -A OUTPUT -d {self._wire_server_address} -p tcp -m owner --uid-owner 0 -j ACCEPT"

    def _get_accept_drop_command(self, command_option: str) -> str:
        return f"firewall-cmd --permanent --direct {command_option} ipv4 -t security -A OUTPUT -d {self._wire_server_address} -p tcp -m conntrack --ctstate INVALID,NEW -j DROP"


class NfTables(FirewallManager):
    """
    Implementation of Firewall using the nft command
    """

    def get_state(self) -> str:
        #
        # The state is similar to
        #
        #    table ip walinuxagent {
        #       chain output {
        #               type filter hook output priority filter; policy accept;
        #               ip daddr 168.63.129.16 tcp dport 53 counter packets 0 bytes 0 accept
        #               ip daddr 168.63.129.16 meta skuid 0 counter packets 93 bytes 57077 accept
        #               ip daddr 168.63.129.16 ct state invalid,new counter packets 5904 bytes 742896 drop
        #           }
        #    }
        #
        return shellutil.run_command(["sudo", "nft", "list", "table", "walinuxagent"])

    _rule_regexp = {
        FirewallManager.ACCEPT_DNS: r" tcp dport != 53 ",
        FirewallManager.ACCEPT: r" meta skuid != 0 ",
        FirewallManager.DROP: r" drop$"
    }

    def get_missing_rules(self) -> List[str]:
        if "table ip walinuxagent" not in shellutil.run_command(["sudo", "nft", "list", "tables"]):
            return [FirewallManager.ACCEPT_DNS, FirewallManager.ACCEPT, FirewallManager.DROP]

        try:
            missing = []

            wireserver_rule = self._get_wireserver_rule()
            for rule, regexp in NfTables._rule_regexp.items():
                if re.search(regexp, wireserver_rule) is None:
                    missing.append(rule)
            return missing
        except FirewallConfigurationError:
            return [FirewallManager.ACCEPT_DNS, FirewallManager.ACCEPT, FirewallManager.DROP]

    def check_rule(self, rule_name: str) -> bool:
        try:
            wireserver_rule = self._get_wireserver_rule()
            return re.search(self._rule_regexp[rule_name], wireserver_rule) is not None
        except KeyError:
            raise Exception(f"Invalid rule name: {rule_name}")

    def _get_wireserver_rule(self) -> str:
        """
        Returns the output line of the nft command that contains the rule for the WireServer address; raises FirewallConfigurationError if the rule is not found.
        """
        for line in self.get_state().split("\n"):
            if re.search(r"\s*ip daddr 168.63.129.16\s*", line) is not None:
                return line
        raise FirewallConfigurationError("Could not find any rules for the WireServer address in the nftables state")

    def delete_rule(self, rule_name: str) -> None:
        output: str = shellutil.run_command(["sudo", "nft", "--json", "--handle", "list", "table", "walinuxagent"])
        #
        # The output will be similar to
        #
        # {
        #   "nftables": [
        #     { "metainfo": { "version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1 } },
        #     { "table": { "family": "ip", "name": "walinuxagent", "handle": 2 } },
        #     { "chain": { "family": "ip", "table": "walinuxagent", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept" } },
        #     {
        #       "rule": {
        #         "family": "ip", "table": "walinuxagent", "chain": "output", "handle": 2,
        #         "expr": [
        #           ...
        #         ]
        #       }
        #     }
        #   ]
        # }
        #
        # Delete the entire rule and add a new one that is missing the desired rule_name
        #
        state = json.loads(output)
        handles = [i["rule"]["handle"] for i in state["nftables"] if i.get("rule") is not None and i["rule"]["table"] == "walinuxagent"]
        if len(handles) != 1:
            raise Exception(f"Expected exactly one rule in the walinuxagent table.\n{output}")

        self._log_and_run_command(f"sudo nft delete rule ip walinuxagent output handle {handles[0]}")

        if rule_name == FirewallManager.ACCEPT_DNS:
            add_rule_command = "sudo nft add rule ip walinuxagent output ip protocol tcp ip daddr 168.63.129.16 skuid != 0 ct state invalid,new counter drop"
        elif rule_name == FirewallManager.ACCEPT:
            add_rule_command = "sudo nft add rule ip walinuxagent output ip protocol tcp ip daddr 168.63.129.16 tcp dport != 53 ct state invalid,new counter drop"
        elif rule_name == FirewallManager.DROP:
            add_rule_command = "sudo nft add rule ip walinuxagent output ip protocol tcp ip daddr 168.63.129.16 tcp dport != 53 skuid != 0 ct state invalid,new counter accept"
        else:
            raise Exception(f"Invalid rule name: {rule_name}")

        self._log_and_run_command(add_rule_command)
