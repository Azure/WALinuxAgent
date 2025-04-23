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
# This script deleting the firewalld rules and ensure deleted rules added back to the firewalld rule set after agent start
#

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_manager import Firewalld
from tests_e2e.tests.lib.logging import log


def main():

    if not Firewalld.is_service_running():
        log.info("firewalld.service is not running and skipping test")
        return

    firewall = Firewalld()
    firewall.log_firewall_state("** firewalld.service is running; initial state of the firewall")

    for rule in [Firewalld.ACCEPT_DNS, Firewalld.ACCEPT, Firewalld.DROP]:
        log.info(f"***** Verifying {rule} rule")
        agent_name = get_osutil().get_service_name()
        # stop the agent, so that it won't re-add rules while checking
        log.info("stop the agent, so that it won't re-add rules while checking")
        shellutil.run_command(["systemctl", "stop", agent_name])

        # deleting rule
        firewall.delete_rule(rule)
        # verifying deletion successful
        firewall.verify_rule_is_not_set(rule)

        # restart the agent to re-add the deleted rules
        log.info("restart the agent to re-add the deleted rules")
        shellutil.run_command(["systemctl", "restart", agent_name])

        firewall.assert_all_rules_are_set()


if __name__ == "__main__":
    main()
