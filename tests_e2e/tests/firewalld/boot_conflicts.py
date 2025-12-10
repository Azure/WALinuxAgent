#!/usr/bin/env python3
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
import re
import time

from assertpy import fail
from datetime import datetime, timedelta

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log, indent
from tests_e2e.tests.lib.ssh_client import SshClient


class BootConflicts(AgentVmTest):
    """
    When firewalld is not installed/running on the VM, the Agent will install the waagent-network-setup service to setup the firewall
    rules during boot. However, if firewalld is installed or started after the Agent has installed waagent-network-setup, both services
    will end up running concurrently during boot, which can lead to an incorrect firewall setup. The waagent-network-setup service
    should detect this condition and exit without setting up any rules. This test verifies that functionality.

    In addition, the RHEL 9 images (and possibly others) include a set of stale firewall rules in /etc/firewalld/direct.xml. This test
    simulates that condition and verifies that the Agent handles those rules correctly. Note that these stale rules include a duplicate
    of the DNS rule (-t security -I OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT).
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def run(self):
        self._setup()

        waagent_log_size = self._get_waagent_log_size()

        log.info("Restarting machine to verify boot behavior...")
        self._context.vm.restart(wait_for_boot=True, ssh_client=self._ssh_client)
        log.info("Boot completed")

        waagent_log = self._wait_for_log_message(waagent_log_size, r"^[0-9TZ:.-]+ INFO Firewall Firewall", "Will not setup the firewall rules")
        log.info(f"waagent-network-setup.service did not setup the firewall rules, as expected:\n{indent(waagent_log)}")

        waagent_log = self._wait_for_log_message(waagent_log_size, r"legacy firewall rule.+--destination-port., .53.", "Removed legacy firewall rule")
        log.info(f"The Agent removed the legacy firewall rule, as expected:\n{indent(waagent_log)}")

        waagent_log = self._wait_for_log_message(waagent_log_size, "waagent-network-setup.service", r"Removing custom firewall service:")
        log.info(f"The Agent removed waagent-network-setup.service, as expected:\n{indent(waagent_log)}")

        waagent_log = self._wait_for_log_message(waagent_log_size, "waagent-network-setup.py", r"Removing custom firewall service:")
        log.info(f"The Agent removed waagent-network-setup.py, as expected:\n{indent(waagent_log)}")

        log.info("Checking permanent firewall rules...")
        firewall_rules = self._ssh_client.run_command("firewall-cmd --direct --permanent --get-all-passthroughs", use_sudo=True)
        log.info(f"Permanent firewall rules:\n{indent(firewall_rules)}")
        firewall_rules = firewall_rules.splitlines()
        if len(firewall_rules) != 3:
            fail(f"There should be exactly 3 permanent firewall rules, got: {firewall_rules}")
        if re.search("-d 168.63.129.16.*--destination-port 53.*-j ACCEPT", firewall_rules[0]) is None:
            fail(f"The first rule should accept connections access to DNS (port 53), got: {firewall_rules[0]}")
        if re.search("-d 168.63.129.16.*--uid-owner 0.*-j ACCEPT", firewall_rules[1]) is None:
            fail(f"The second firewall rule should accept connections from root, got: {firewall_rules[1]}")
        if re.search("-d 168.63.129.16.*-j DROP", firewall_rules[2]) is None:
            fail("The third firewall rule should drop all connections")

    def _setup(self):
        log.info("Beginning test setup...")
        log.info("Stopping waagent service to prevent it from changing the firewall rules during test setup...")
        self._ssh_client.run_command("systemctl stop waagent", use_sudo=True)

        # Firewalld has been removed from some images in the marketplaces derived from RHEL (these images come with the stale rules, though)
        # We simulate this setup by uninstalling firewalld.
        log.info("Uninstalling firewalld...")
        output = self._ssh_client.run_command("yum remove -y firewalld", use_sudo=True)
        log.info(f"Firewalld was uninstalled:\n{indent(output)}")

        stale_rules = \
"""<?xml version="1.0" encoding="utf-8"?>
<direct>
<passthrough ipv="ipv4">-t security -I OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT</passthrough>
<passthrough ipv="ipv4">-t security -A OUTPUT -d 168.63.129.16 -p tcp --destination-port 53 -j ACCEPT</passthrough>
<passthrough ipv="ipv4">-t security -A OUTPUT -d 168.63.129.16 -p tcp -m owner --uid-owner 0 -j ACCEPT</passthrough>
<passthrough ipv="ipv4">-t security -A OUTPUT -d 168.63.129.16 -p tcp -m conntrack --ctstate INVALID,NEW -j DROP</passthrough>
</direct>"""
        log.info("Creating stale permanent firewall rules in /etc/firewalld/direct.xml...")
        # create /etc/firewalld if it does not exist and remove any existing direct.xml files
        self._ssh_client.run_command("mkdir -p /etc/firewalld", use_sudo=True)
        self._ssh_client.run_command("find /etc/firewalld -name 'direct.xml*' -exec rm -f {} \\;", use_sudo=True)
        output = self._ssh_client.run_command(f"echo '{stale_rules}' | sudo tee /etc/firewalld/direct.xml")
        log.info(f"Stale firewall rules created:\n{indent(output)}")

        waagent_log_size = self._get_waagent_log_size()

        log.info("Starting waagent service to install waagent-network-setup.service...")
        self._ssh_client.run_command("systemctl start waagent", use_sudo=True)

        waagent_log = self._wait_for_log_message(waagent_log_size, r"waagent-network-setup.service", r"Successfully added and enabled the waagent-network-setup.service|waagent-network-setup.service already enabled. No change needed")
        log.info(f"waagent-network-setup.service was installed:\n{indent(waagent_log)}")

        log.info("Re-installing firewalld...")
        output = self._ssh_client.run_command("yum install -y firewalld", use_sudo=True)
        log.info(f"Firewalld was installed:\n{output}")
        log.info("Completed test setup.")

    def _get_waagent_log_size(self) -> int:
        return int(self._ssh_client.run_command("stat --format '%s' /var/log/waagent.log").rstrip())

    def _wait_for_log_message(self, offset: int, selector_re: str, message: str) -> str:
        log.info(f"Checking waagent.log starting at offset {offset}")

        limit = datetime.now() + timedelta(minutes=5)
        delay = timedelta(seconds=15)

        while True:
            waagent_log = self._ssh_client.run_command(r"tail --bytes=+{0} /var/log/waagent.log | tr -d '\000' | grep -E '{1}' || true".format(offset, selector_re))  # some tests write NULL characters to the log; we delete them
            if re.search(message, waagent_log) is not None:
                return waagent_log
            if datetime.now() > limit - delay:
                break
            log.info(f"Can't find message in Agent's log ('{message}'). Will retry after a short pause.")
            time.sleep(delay.seconds)
        raise TimeoutError(f"Timed out waiting for waagent message '{message}'")


if __name__ == "__main__":
    BootConflicts.run_from_command_line()
