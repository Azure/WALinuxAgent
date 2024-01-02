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

from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.agent_test import AgentVmTest, TestSkipped
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class PublishHostname(AgentVmTest):
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._context = context
        self._ssh_client = context.create_ssh_client()
        self._private_ip = context.vm.get_private_ip_address()
        self._vm_password = ""

    def add_vm_password(self):
        # Add password to VM to help with debugging in case of failure
        # REMOVE PWD FROM LOGS IF WE EVER MAKE THESE RUNS/LOGS PUBLIC
        username = self._ssh_client.username
        pwd = self._ssh_client.run_command("openssl rand -base64 32 | tr : .").rstrip()
        self._vm_password = pwd
        log.info("VM Username: {0}; VM Password: {1}".format(username, pwd))
        self._ssh_client.run_command("echo '{0}:{1}' | sudo -S chpasswd".format(username, pwd))

    def check_and_install_dns_tools(self):
        lookup_cmd = "dig -x {0}".format(self._private_ip)
        dns_regex = r"[\S\s]*;; ANSWER SECTION:\s.*PTR\s*(?P<hostname>.*).internal.*[\S\s]*"

        # Not all distros come with dig. Install dig if not on machine
        try:
            self._ssh_client.run_command("dig -v")
        except CommandError as e:
            if "dig: command not found" in e.stderr:
                distro = self._ssh_client.run_command("get_distro.py").rstrip().lower()
                if "debian_9" in distro:
                    # Debian 9 hostname look up needs to be done with "host" instead of dig
                    lookup_cmd = "host {0}".format(self._private_ip)
                    dns_regex = r".*pointer\s(?P<hostname>.*).internal.*"
                elif "debian" in distro:
                    self._ssh_client.run_command("apt install -y dnsutils", use_sudo=True)
                elif "alma" in distro or "rocky" in distro:
                    self._ssh_client.run_command("dnf install -y bind-utils", use_sudo=True)
                else:
                    raise
            else:
                raise

        return lookup_cmd, dns_regex

    def check_agent_reports_status(self):
        status_updated = False
        last_agent_status_time = self._context.vm.get_instance_view().vm_agent.statuses[0].time
        log.info("Agent reported status at {0}".format(last_agent_status_time))
        retries = 3

        while retries > 0 and not status_updated:
            agent_status_time = self._context.vm.get_instance_view().vm_agent.statuses[0].time
            if agent_status_time != last_agent_status_time:
                status_updated = True
                log.info("Agent reported status at {0}".format(last_agent_status_time))
            else:
                retries -= 1
                sleep(60)

        if not status_updated:
            fail("Agent hasn't reported status since {0} and ssh connection failed. Use the serial console in portal "
                 "to check the contents of '/sys/class/net/eth0/operstate'. If the contents of this file are 'up', "
                 "no further action is needed. If contents are 'down', that indicates the network interface is down "
                 "and more debugging needs to be done to confirm this is not caused by the agent.\n VM: {1}\n RG: {2}"
                 "\nSubscriptionId: {3}\nUsername: {4}\nPassword: {5}".format(last_agent_status_time,
                                                                              self._context.vm,
                                                                              self._context.vm.resource_group,
                                                                              self._context.vm.subscription,
                                                                              self._context.username,
                                                                              self._vm_password))

    def retry_ssh_if_connection_reset(self, command: str, use_sudo=False):
        # The agent may bring the network down and back up to publish the hostname, which can reset the ssh connection.
        # Adding retry here for connection reset.
        retries = 3
        while retries > 0:
            try:
                return self._ssh_client.run_command(command, use_sudo=use_sudo)
            except CommandError as e:
                retries -= 1
                retryable = e.exit_code == 255 and "Connection reset by peer" in e.stderr
                if not retryable or retries == 0:
                    raise
                log.warning("The SSH operation failed, retrying in 30 secs")
                sleep(30)

    def run(self):
        # TODO: Investigate why hostname is not being published on Ubuntu as expected
        if "ubuntu" in self._ssh_client.run_command("get_distro.py").lower():
            raise TestSkipped("Known issue with hostname publishing on ubuntu. Will skip test until we continue "
                              "investigation.")

        # Add password to VM and log. This allows us to debug with serial console if necessary
        self.add_vm_password()

        # This test looks up what hostname is published to dns. Check that the tools necessary to get hostname are
        # installed, and if not install them.
        lookup_cmd, dns_regex = self.check_and_install_dns_tools()

        # Check if this distro monitors hostname changes. If it does, we should check that the agent detects the change
        # and publishes the host name. If it doesn't, we should check that the hostname is automatically published.
        monitors_hostname = self._ssh_client.run_command("get-waagent-conf-value Provisioning.MonitorHostName", use_sudo=True).rstrip().lower()

        hostname_change_ctr = 0
        # Update the hostname 3 times
        while hostname_change_ctr < 3:
            try:
                hostname = "hostname-monitor-{0}".format(hostname_change_ctr)
                log.info("Update hostname to {0}".format(hostname))
                self.retry_ssh_if_connection_reset("hostnamectl set-hostname {0}".format(hostname), use_sudo=True)

                # Wait for the agent to detect the hostname change for up to 2 minutes if hostname monitoring is enabled
                if monitors_hostname == "y" or monitors_hostname == "yes":
                    log.info("Agent hostname monitoring is enabled")
                    timeout = datetime.datetime.now() + datetime.timedelta(minutes=2)
                    hostname_detected = ""
                    while datetime.datetime.now() <= timeout:
                        try:
                            hostname_detected = self.retry_ssh_if_connection_reset("grep -n 'Detected hostname change:.*-> {0}' /var/log/waagent.log".format(hostname), use_sudo=True)
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
                else:
                    log.info("Agent hostname monitoring is disabled")

                # Check that the expected hostname is published with 4 minute timeout
                timeout = datetime.datetime.now() + datetime.timedelta(minutes=4)
                published_hostname = ""
                while datetime.datetime.now() <= timeout:
                    try:
                        dns_info = self.retry_ssh_if_connection_reset(lookup_cmd)
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
                # If failure is ssh issue, we should confirm that the VM did not lose network connectivity due to the
                # agent's operations on the network. If agent reports status after this failure, then we know the
                # network is up.
                if e.exit_code == 255 and ("Connection timed out" in e.stderr or "Connection refused" in e.stderr):
                    self.check_agent_reports_status()
                raise


if __name__ == "__main__":
    PublishHostname.run_from_command_line()
