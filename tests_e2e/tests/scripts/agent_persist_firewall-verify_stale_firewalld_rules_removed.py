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
# This script verifies that stale firewalld passthrough rules created by an older agent are removed when nftables is
# the runtime firewall manager.
#

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_manager import FirewallManager, Firewalld, NfTables
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def main():
    if not Firewalld.is_service_running():
        log.info("firewalld.service is not running; skipping the stale firewalld rule cleanup test")
        return

    if not isinstance(FirewallManager.create(), NfTables):
        log.info("Runtime firewall rules do not use nftables; skipping the stale firewalld rule cleanup test")
        return

    firewall = Firewalld()
    rules = [Firewalld.ACCEPT_DNS, Firewalld.ACCEPT, Firewalld.DROP]
    agent_name = get_osutil().get_service_name()

    firewall.log_firewall_state("** firewalld.service is running; initial state of the firewall")
    log.info("Stopping the agent before adding stale firewalld passthrough rules")
    shellutil.run_command(["systemctl", "stop", agent_name])

    try:
        for rule in rules:
            firewall.add_rule(rule)
            if not firewall.check_rule(rule):
                raise Exception("Failed to add the stale {0} firewalld passthrough rule".format(rule))
    finally:
        log.info("Restarting the agent to remove stale firewalld passthrough rules")
        shellutil.run_command(["systemctl", "restart", agent_name])

    rules_are_removed = retry_if_false(
        lambda: all(not firewall.check_rule(rule) for rule in rules),
        attempts=5,
        delay=30)

    if not rules_are_removed:
        raise Exception("The agent did not remove the stale firewalld passthrough rules. Current state: {0}".format(
            firewall.get_state()))

    log.info("The agent removed all stale firewalld passthrough rules")


if __name__ == "__main__":
    main()
