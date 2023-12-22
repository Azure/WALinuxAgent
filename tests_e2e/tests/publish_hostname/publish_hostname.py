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

#
# This test updates the hostname and checks that the agent published the hostname to DNS. It also checks that the
# primary network is up after publishing the hostname. This test was added in response to a bug in publishing the
# hostname on fedora distros, where there was a race condition between NetworkManager restart and Network Interface
# restart which caused the primary interface to go down.
#

import datetime
import re

from assertpy import fail
from time import sleep

from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class PublishHostname(AgentVmTest):
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._context = context
        self._ssh_client = context.create_ssh_client()
        self._private_ip = context.private_ip_address

    def check_and_install_tools(self):
        lookup_cmd = "dig -x {0}".format(self._private_ip)
        dns_regex = r"[\S\s]*;; ANSWER SECTION:\s.*PTR\s*(?P<hostname>.*).internal.cloudapp.net.[\S\s]*"

        # Not all distros come with dig. Install dig if not on machine
        try:
            self._ssh_client.run_command("dig -v")
        except CommandError as e:
            if "dig: command not found" in e.stderr:
                distro = self._ssh_client.run_command("cat /etc/*-release", use_sudo=True)
                if "Debian GNU/Linux 9" in distro:
                    # Debian 9 hostname look up needs to be done with "host" instead of dig
                    lookup_cmd = "host {0}".format(self._private_ip)
                    dns_regex = r".*pointer\s(?P<hostname>.*).internal.cloudapp.net."
                elif "Debian" in distro:
                    self._ssh_client.run_command("apt install -y dnsutils", use_sudo=True)
                elif "AlmaLinux" in distro or "Rocky" in distro:
                    self._ssh_client.run_command("dnf install -y bind-utils", use_sudo=True)
                else:
                    raise
            else:
                raise

        return lookup_cmd, dns_regex

    def run(self):
        # Enable agent hostname monitoring
        log.info("Executing script update-waagent-conf to enable agent hostname monitoring")
        result = self._ssh_client.run_command("update-waagent-conf Provisioning.MonitorHostName=y Provisioning.MonitorHostNamePeriod=30", use_sudo=True)
        log.info("Successfully enabled agent hostname monitoring config flag: {0}".format(result))

        # This test looksup what hostname is published to dns. Check that the tools necessary to get hostname are
        # installed, and if not install them.
        lookup_cmd, dns_regex = self.check_and_install_tools()

        hostname_change_ctr = 0
        # Update the hostname 3 times
        while hostname_change_ctr < 3:
            try:
                hostname = "lisa-hostname-monitor-{0}".format(hostname_change_ctr)
                log.info("Update hostname to {0}".format(hostname))
                self._ssh_client.run_command("hostnamectl set-hostname {0}".format(hostname), use_sudo=True)

                # Wait for the agent to detect the hostname change for up to 2 minutes
                timeout = datetime.datetime.now() + datetime.timedelta(minutes=2)
                hostname_detected = ""
                while datetime.datetime.now() <= timeout:
                    try:
                        hostname_detected = self._ssh_client.run_command("grep -n {0} /var/log/waagent.log".format(hostname), use_sudo=True)
                        if hostname_detected:
                            log.info("Agent detected hostname change: {0}".format(hostname_detected))
                            break
                    except CommandError as e:
                        # Exit code 1 indicates grep did not find a match. Sleep if exit code is 1, otherwise raise.
                        if e.exit_code != 1:
                            raise
                    sleep(15)

                if not hostname_detected:
                    fail("Agent did not detect hostname change: {0}".format(hostname))

                # Check that the expected hostname is published with 2 minute timeout
                timeout = datetime.datetime.now() + datetime.timedelta(minutes=2)
                published_hostname = ""
                while datetime.datetime.now() <= timeout:
                    try:
                        dns_info = self._ssh_client.run_command(lookup_cmd)
                        actual_hostname = re.match(dns_regex, dns_info)
                        if actual_hostname:
                            # Compare published hostname to expected hostname
                            published_hostname = actual_hostname.group('hostname')
                            if hostname == published_hostname:
                                log.info("SUCCESS Hostname {0} was published successfully".format(hostname))
                                break
                        else:
                            log.info("Unable to parse the dns info: {0}".format(dns_info))
                    except CommandError as e:
                        if "NXDOMAIN" in e.stdout:
                            log.info("DNS Lookup could not find domain. Will try again.")
                        else:
                            raise
                    sleep(30)

                if published_hostname == "" or published_hostname != hostname:
                    fail("Hostname {0} was not published successfully. Actual host name is: {1}".format(hostname, published_hostname))

                hostname_change_ctr += 1

            except CommandError as e:
                # If command failed to due to ssh issue, we should confirm it is not the agent's operations on the
                # network which are causing ssh issues. The following steps can be taken to determine if the network
                # is down:
                # 1. Go to test Vm in portal
                # 2. Add password to VM via portal
                # 3. Use serial console in portal to run 'cat /sys/class/net/eth0/operstate'
                # 4. If contents are 'down', then the network interface is down, and we should investigate if that was
                # caused by the agent.
                if e.exit_code == 255 and ("Connection timed out" in e.stderr or "Connection refused" in e.stderr):
                    fail("Cannot ssh to VM. To confirm this is a transient SSH issue, and not caused by the agent "
                         "doing network operations, take the following steps:\n1. Go to portal for this VM (vm: {0}, "
                         "rg: {1}, sub: {2}.\n2. Add password to VM via portal.\n3. Use serial console via portal to "
                         "check contents of '/sys/class/net/eth0/operstate'. If the contents of this file are 'up', "
                         "no further action is needed. If contents are 'down', that indicates the network interface is "
                         "down and more debugging needs to be done to confirm this is not caused by the agent. "
                         .format(self._context.vm, self._context.vm.resource_group, self._context.vm.subscription))
                raise


if __name__ == "__main__":
    PublishHostname.run_from_command_line()
