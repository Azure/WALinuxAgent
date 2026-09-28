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
# This script verifies firewalld rules set on the vm if firewalld service is running and if it's not running, it verifies network-setup service is enabled by the agent
#
import argparse

from assertpy import fail

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_manager import FirewallManager, Firewalld, NfTables
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def verify_network_setup_service_enabled():
    """
    Checks if network-setup service is enabled in the vm
    """
    agent_name = get_osutil().get_service_name()
    service_name = "{0}-network-setup.service".format(agent_name)
    cmd = ["systemctl", "is-enabled", service_name]

    def op(command):
        try:
            return shellutil.run_command(command).rstrip() == "enabled"
        except shellutil.CommandError:
            return False

    try:
        status = retry_if_false(lambda: op(cmd), attempts=5, delay=30)
    except Exception as e:
        log.warning("Error -- while checking network.service is-enabled status {0}".format(e))
        status = False
    if not status:
        cmd = ["systemctl", "status", service_name]
        fail("network-setup.service is not enabled!. Current status: {0}".format(shellutil.run_command(cmd)))

    log.info("network-setup.service is enabled")


def verify_firewalld_rules_not_present():
    firewall = Firewalld()
    rules = [Firewalld.ACCEPT_DNS, Firewalld.ACCEPT, Firewalld.DROP]

    rules_are_not_present = retry_if_false(
        lambda: all(not firewall.check_rule(rule) for rule in rules),
        attempts=5,
        delay=30)

    if not rules_are_not_present:
        fail("Agent-owned firewalld passthrough rules should not be present when runtime uses nftables. Current state: {0}".format(
            firewall.get_state()))

    log.info("Asserted that agent-owned firewalld passthrough rules are not present")


def verify_firewall_service_running(expect_firewalld_running):
    log.info("Ensure test agent initialize the firewalld/network service setup")

    firewall_manager = FirewallManager.create()
    firewalld_service_running = Firewalld.is_service_running()
    if expect_firewalld_running and not firewalld_service_running:
        fail("Firewalld was running before test setup, but it is no longer running")

    if isinstance(firewall_manager, NfTables) or not firewalld_service_running:
        # Checking if network-setup service is enabled if firewall service is not active or Nftables in use
        log.info("Checking if network setup service is enabled by the agent since firewall service is not active or Nftables in use")
        verify_network_setup_service_enabled()
    else:
        # Checking if firewalld rules are present in the rule set if firewall service is active and Nftables not in use
        Firewalld().assert_all_rules_are_set()

    if isinstance(firewall_manager, NfTables) and firewalld_service_running:
        # The agent should not create any firewalld passthrough rules when NfTables is the selected firewall manager,
        # since those rules are only compatible with iptables.
        log.info("Asserting that firewalld passthrough rules do not exist when custom setup network service is used for persistent rules")
        verify_firewalld_rules_not_present()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-firewalld-running", action="store_true")
    args = parser.parse_args()
    verify_firewall_service_running(args.expect_firewalld_running)
