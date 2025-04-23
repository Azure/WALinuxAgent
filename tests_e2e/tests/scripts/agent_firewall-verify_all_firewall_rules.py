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
#
# This script checks all agent firewall rules added properly and working as expected
#
import argparse
import contextlib
import os
import pwd
import re
import socket

from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import format_exception
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION
from tests_e2e.tests.lib.firewall_manager import FirewallManager, IpTables, get_wireserver_ip
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
import http.client as httpclient


def _get_effective_user() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


@contextlib.contextmanager
def switch_user(user: str) -> None:
    """
    Switches the effective UID to the given user
    """
    current_uid = os.getuid()
    try:
        uid = pwd.getpwnam(user).pw_uid
        os.seteuid(uid)
        log.info(f"Switched to user '{user}' (UID {uid})")
        yield
    except Exception as e:
        raise Exception(f"Cannot switch to user {user}: {e}")
    finally:
        try:
            os.seteuid(current_uid)
            log.info(f"Switched back to user '{_get_effective_user()}'")
        except Exception as e:
            raise Exception(f"Cannot switch back to the original user: {e}")


class AgentFirewall:
    def __init__(self, non_root_user: str):
        self._firewall_manager: FirewallManager = FirewallManager.create()
        self._non_root_user: str = non_root_user

    def run(self):
        self._prepare_agent()

        self._firewall_manager.log_firewall_state("** Initial state of the firewall")
        # Some versions of RHEL have a baked-in agent (2.7.0.6) that can produce duplicate DNS rules.
        if DISTRO_NAME in ["rhel", "redhat"] and FlexibleVersion(DISTRO_VERSION).major >= 8:
            self._remove_duplicate_dns_rules()
        self._firewall_manager.assert_all_rules_are_set()

        self._test_accept_dns_rule()
        self._test_accept_rule()
        self._test_drop_rule()

    def _remove_duplicate_dns_rules(self) -> None:
        log.info("Checking for duplicate DNS rules...")
        if not isinstance(self._firewall_manager, IpTables):
            raise Exception(f"Expected a FirewallManager of type IpTables on {DISTRO_NAME} {DISTRO_VERSION}. It is {type(self._firewall_manager)}")
        state = self._firewall_manager.get_state()
        matches = [line for line in state.splitlines() if re.search(r"ACCEPT.+168\.63\.129\.16.*tcp dpt:53",  line) is not None]
        if len(matches) < 2:
            log.info("No duplicates found")
            return
        duplicates = '\n'.join(matches)
        log.info(f"Found duplicates:\n{duplicates}")
        log.info("Removing 1 duplicate...")
        self._firewall_manager.delete_rule(FirewallManager.ACCEPT_DNS)
        self._firewall_manager.log_firewall_state("** State of the firewall")

    @staticmethod
    def _verify_dns_request_to_wireserver(should_succeed: bool) -> None:
        """
        Verifies DNS requests to the wireserver
        """
        current_user = _get_effective_user()

        log.info(f"-----Verifying DNS requests to wireserver from user '{current_user}'. Should succeed: {should_succeed}")

        try:
            socket.create_connection((get_wireserver_ip(), 53), timeout=10)
            succeeded = True
        except Exception as e:
            # The request should time out if the request is blocked by the firewall
            if isinstance(e, socket.timeout):
                succeeded = False
            else:
                raise Exception(f"Unexpected error while issuing a DNS request to wireserver: {format_exception(e)}")

        if succeeded == should_succeed:
            if succeeded:
                log.info(f"Success -- can connect to wireserver port 53 as user '{current_user}'")
            else:
                log.info(f"Success -- access to wireserver port 53 is blocked for user '{current_user}'")
        else:
            if succeeded:
                raise Exception(f"Error -- unprivileged user:({current_user}) could connect to wireserver port 53, make sure the firewall rules are set correctly")
            else:
                raise Exception(f"Cannot issue a DNS request as user '{current_user}'), make sure the firewall rules are set correctly [DNS request timed out]")

    @staticmethod
    def _verify_http_request_to_wireserver(should_succeed: bool) -> None:
        """
        Verifies HTTP requests to the wireserver
        """
        current_user = _get_effective_user()

        log.info(f"-----Verifying HTTP request to wireserver from user '{current_user}'. Should succeed: {should_succeed}")

        try:
            client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=10)
            client.request('GET', '/?comp=versions')
            succeeded = True
        except Exception as e:
            if isinstance(e, socket.timeout):
                succeeded = False
            else:
                raise Exception(f"Unexpected error while connecting to wireserver: {format_exception(e)}")

        if succeeded == should_succeed:
            if succeeded:
                log.info(f"Success -- access to wireserver as user '{current_user}'  is allowed")
            else:
                log.info(f"Success -- access to wireserver is blocked for user '{current_user}' ")
        else:
            if succeeded:
                raise Exception(f"Error -- user '{current_user}' could connect to wireserver, make sure the firewall rules are set correctly")
            else:
                raise Exception(f"Cannot connect to wireserver as user '{current_user}', make sure the firewall rules are set correctly")

    def _test_accept_dns_rule(self) -> None:
        """
        Deletes the ACCEPT_DNS firewall rule and makes sure it is re-added by agent.
        """
        log.info("-----Verifying behavior of the ACCEPT_DNS rule")
        log.info("Before deleting the rule, ensure a non root user can do a DNS request to wireserver, but cannot do an HTTP request")
        with switch_user(self._non_root_user):
            self._verify_dns_request_to_wireserver(should_succeed=True)
            self._verify_http_request_to_wireserver(should_succeed=False)

        # stop the agent, so that it won't re-add rules while checking
        log.info("Stop Guest Agent service")
        # agent-service is script name and stop is argument
        stop_agent = ["agent-service", "stop"]
        shellutil.run_command(stop_agent)

        # deleting non root accept rule
        log.info(f"-----Deleting firewall rule {FirewallManager.ACCEPT_DNS}...")
        self._firewall_manager.delete_rule(FirewallManager.ACCEPT_DNS)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.ACCEPT_DNS}")
        self._firewall_manager.verify_rule_is_not_set(self._firewall_manager.ACCEPT_DNS)

        self._firewall_manager.log_firewall_state("** Current firewall rules")

        log.info("After deleting the ACCEPT_DNS rule, ensure a non-root user cannot do a DNS request to wireserver")
        with switch_user(self._non_root_user):
            self._verify_dns_request_to_wireserver(should_succeed=False)

        # restart the agent to re-add the deleted rules
        log.info("Restart Guest Agent service to re-add the deleted rules")
        # agent-service is script name and start is argument
        start_agent = ["agent-service", "start"]
        shellutil.run_command(start_agent)

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current IP table rules")

        log.info("After appending the rule back , ensure a non root user can do a DNS request to wireserver, but cannot do an HTTP request\n")
        with switch_user(self._non_root_user):
            self._verify_dns_request_to_wireserver(should_succeed=True)
            self._verify_http_request_to_wireserver(should_succeed=False)

        log.info("Ensuring missing rules are re-added by the running agent")
        # deleting non root accept rule
        log.info(f"-----Deleting firewall rule {FirewallManager.ACCEPT_DNS}...")
        self._firewall_manager.delete_rule(FirewallManager.ACCEPT_DNS)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.ACCEPT_DNS}")

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current firewall rules")

        log.info("ACCEPT_DNS rule verified successfully\n")

    def _test_accept_rule(self):
        """
        Deletes the ACCEPT firewall rule and makes sure it is re-added by agent.
        """
        log.info("-----Verifying behavior of the ACCEPT rule")
        log.info("Before deleting the rule, ensure root can do an HTTP request, but a non-root user cannot")
        self._verify_http_request_to_wireserver(should_succeed=True)
        with switch_user(self._non_root_user):
            self._verify_http_request_to_wireserver(should_succeed=False)

        # stop the agent, so that it won't re-add rules while checking
        log.info("Stop Guest Agent service")
        # agent-service is script name and stop is argument
        stop_agent = ["agent-service", "stop"]
        shellutil.run_command(stop_agent)

        # deleting ACCEPT rule
        log.info(f"-----Deleting firewall rule {FirewallManager.ACCEPT}...")
        self._firewall_manager.delete_rule(FirewallManager.ACCEPT)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.ACCEPT}")
        self._firewall_manager.verify_rule_is_not_set(FirewallManager.ACCEPT)
        # deleting drop rule too otherwise after restart, the daemon will go into loop since it cannot connect to wireserver. This would block the agent initialization.
        log.info(f"-----Deleting firewall rule {FirewallManager.DROP}...")
        self._firewall_manager.delete_rule(FirewallManager.DROP)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.DROP}")
        self._firewall_manager.verify_rule_is_not_set(FirewallManager.DROP)

        self._firewall_manager.log_firewall_state("** Current firewall rules")

        # restart the agent to re-add the deleted rules
        log.info("Restart Guest Agent service to re-add the deleted rules")
        # agent-service is script name and start is argument
        start_agent = ["agent-service", "start"]
        shellutil.run_command(start_agent)

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current IP table rules")

        log.info("After appending the rule back, ensure root can do an HTTP request, but a non-root user cannot")
        with switch_user(self._non_root_user):
            self._verify_dns_request_to_wireserver(should_succeed=True)
            self._verify_http_request_to_wireserver(should_succeed=False)
        self._verify_http_request_to_wireserver(should_succeed=True)

        log.info("Ensuring missing rules are re-added by the running agent")
        log.info(f"-----Deleting firewall rule {FirewallManager.ACCEPT}...")
        self._firewall_manager.delete_rule(FirewallManager.ACCEPT)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.ACCEPT}")

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current firewall rules")

        log.info("ACCEPT_DNS rule verified successfully\n")

    def _test_drop_rule(self):
        """
        Deletes the DROP firewall rule and makes sure it is re-added by agent.
        """
        log.info("-----Verifying behavior of the ACCEPT rule")

        # stop the agent, so that it won't re-add rules while checking
        log.info("Stop Guest Agent service")
        # agent-service is script name and stop is argument
        stop_agent = ["agent-service", "stop"]
        shellutil.run_command(stop_agent)

        # deleting DROP rule
        log.info(f"-----Deleting firewall rule {FirewallManager.DROP}...")
        self._firewall_manager.delete_rule(FirewallManager.DROP)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.DROP}")
        self._firewall_manager.verify_rule_is_not_set(FirewallManager.DROP)

        self._firewall_manager.log_firewall_state("** Current firewall rules")

        log.info("After deleting the non root drop rule, ensure a non-root user can do an HTTP request to wireserver")
        with switch_user(self._non_root_user):
            self._verify_http_request_to_wireserver(should_succeed=True)

        # restart the agent to re-add the deleted rules
        log.info("Restart Guest Agent service to re-add the deleted rules")
        # agent-service is script name and start is argument
        start_agent = ["agent-service", "start"]
        shellutil.run_command(start_agent)

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current IP table rules")

        log.info("After appending the rule back , ensure a non root user can do a DNS to wireserver, but cannot do an HTTP request")
        with switch_user(self._non_root_user):
            self._verify_dns_request_to_wireserver(should_succeed=True)
            self._verify_http_request_to_wireserver(should_succeed=False)
        self._verify_http_request_to_wireserver(should_succeed=True)

        log.info("Ensuring missing rules are re-added by the running agent")
        log.info(f"-----Deleting firewall rule {FirewallManager.DROP}...")
        self._firewall_manager.delete_rule(FirewallManager.DROP)
        log.info(f"Success -- Deleted firewall rule {FirewallManager.DROP}")

        self._firewall_manager.assert_all_rules_are_set()
        self._firewall_manager.log_firewall_state("** Current firewall rules")

        log.info("DROP rule verified successfully\n")

    @staticmethod
    def _prepare_agent():
        log.info("Executing script update-waagent-conf to enable agent firewall config flag")
        # Changing the firewall period from default 5 mins to 1 min, so that test won't wait for that long to verify rules
        shellutil.run_command(["update-waagent-conf", "OS.EnableFirewall=y", f"OS.EnableFirewallPeriod={FirewallManager.FIREWALL_PERIOD}"])
        log.info("Successfully enabled agent firewall config flag")


parser = argparse.ArgumentParser()
parser.add_argument('-u', '--user', required=True, help="Non root user")
args = parser.parse_args()
run_remote_test(lambda: AgentFirewall(args.user).run())

