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
from assertpy import fail

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_helpers import execute_cmd_return_err_code, \
    firewalld_service_running, verify_all_firewalld_rules_exist
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def verify_network_setup_service_enabled():
    """
    Checks if network-setup service is enabled in the vm
    """
    agent_name = get_osutil().get_service_name()
    service_name = "{0}-network-setup.service".format(agent_name)
    cmd = ["systemctl", "is-enabled", service_name]

    def op(cmd):
        exit_code, output = execute_cmd_return_err_code(cmd)
        return exit_code == 0 and output.rstrip() == "enabled"

    try:
        status = retry_if_false(lambda: op(cmd), attempts=5, delay=30)
    except Exception as e:
        log.warning("Error -- while checking network.service is-enabled status {0}".format(e))
        status = False
    if not status:
        cmd = ["systemctl", "status", service_name]
        fail("network-setup.service is not enabled!. Current status: {0}".format(shellutil.run_command(cmd)))

    log.info("network-setup.service is enabled")


def verify_firewall_service_running():
    log.info("Ensure test agent initialize the firewalld/network service setup")

    # Check if firewall active on the Vm
    log.info("Checking if firewall service is active on the VM")
    if firewalld_service_running():
        # Checking if firewalld rules are present in rule set if firewall service is active
        verify_all_firewalld_rules_exist()
    else:
        # Checking if network-setup service is enabled if firewall service is not active
        log.info("Checking if network-setup service is enabled by the agent since firewall service is not active")
        verify_network_setup_service_enabled()


if __name__ == "__main__":
    verify_firewall_service_running()
