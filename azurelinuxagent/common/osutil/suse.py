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

import time

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil  # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError  # pylint: disable=W0611
from azurelinuxagent.common.future import ustr  # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class SUSE11OSUtil(DefaultOSUtil):
    def __init__(self):
        super(SUSE11OSUtil, self).__init__()
        self.jit_enabled = True
        self.dhclient_name = 'dhcpcd'

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/HOSTNAME', hostname)
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", self.dhclient_name])

    def is_dhcp_enabled(self):
        return True

    def stop_dhcp_service(self):
        self._run_command_without_raising(["/sbin/service", self.dhclient_name, "stop"], log_error=False)

    def start_dhcp_service(self):
        self._run_command_without_raising(["/sbin/service", self.dhclient_name, "start"], log_error=False)

    def start_network(self):
        self._run_command_without_raising(["/sbin/service", "network", "start"], log_error=False)

    def restart_ssh_service(self):
        self._run_command_without_raising(["/sbin/service", "sshd", "restart"], log_error=False)

    def stop_agent_service(self):
        self._run_command_without_raising(["/sbin/service", self.service_name, "stop"], log_error=False)

    def start_agent_service(self):
        self._run_command_without_raising(["/sbin/service", self.service_name, "start"], log_error=False)

    def register_agent_service(self):
        self._run_command_without_raising(["/sbin/insserv", self.service_name], log_error=False)

    def unregister_agent_service(self):
        self._run_command_without_raising(["/sbin/insserv", "-r", self.service_name], log_error=False)


class SUSEOSUtil(SUSE11OSUtil):
    def __init__(self):
        super(SUSEOSUtil, self).__init__()
        self.dhclient_name = 'wickedd-dhcp4'

    def publish_hostname(self, hostname, recover_nic=False):
        self.set_dhcp_hostname(hostname)
        self.set_hostname_record(hostname)
        ifname = self.get_if_name()
        # To push the hostname to the dhcp server we do not need to
        # bring down the interface, just make the make ifup do whatever is
        # necessary
        self.ifup(ifname)

    def ifup(self, ifname, retries=3, wait=5):
        logger.info('Interface {0} bounce with ifup'.format(ifname))
        retry_limit=retries+1
        for attempt in range(1, retry_limit):
            try:
                shellutil.run_command(['ifup', ifname], log_error=True)
            except Exception:
                if attempt < retry_limit:
                    logger.info("retrying in {0} seconds".format(wait))
                    time.sleep(wait)
                else:
                    logger.warn("exceeded restart retries")

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    def set_hostname(self, hostname):
        self._run_command_without_raising(
            ["hostnamectl", "set-hostname", hostname], log_error=False
        )

    def set_dhcp_hostname(self, hostname):
        dhcp_config_file_path = '/etc/sysconfig/network/dhcp'
        hostname_send_setting = fileutil.get_line_startingwith(
            'DHCLIENT_HOSTNAME_OPTION', dhcp_config_file_path
        )
        if hostname_send_setting:
            value = hostname_send_setting.split('=')[-1]
            # wicked's source accepts values with double quotes, single quotes, and no quotes at all.
            if value in ('"AUTO"', "'AUTO'", 'AUTO') or value == '"{0}"'.format(hostname):
                # Return if auto send host-name is configured or the current
                # hostname is already set up to be sent
                return
            else:
                # Do not use update_conf_file as it moves the setting to the
                # end of the file separating it from the contextual comment
                new_conf = []
                dhcp_conf = fileutil.read_file(
                    dhcp_config_file_path).split('\n')
                for entry in dhcp_conf:
                    if entry.startswith('DHCLIENT_HOSTNAME_OPTION'):
                        new_conf.append(
                           'DHCLIENT_HOSTNAME_OPTION="{0}"'. format(hostname)
                        )
                        continue
                    new_conf.append(entry)
                fileutil.write_file(dhcp_config_file_path, '\n'.join(new_conf))
        else:
            fileutil.append_file(
                dhcp_config_file_path,
                'DHCLIENT_HOSTNAME_OPTION="{0}"'. format(hostname)
            )

    def stop_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "stop", "{}.service".format(self.dhclient_name)],
                                          log_error=False)

    def start_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "start", "{}.service".format(self.dhclient_name)],
                                          log_error=False)

    def start_network(self):
        self._run_command_without_raising(["systemctl", "start", "network.service"], log_error=False)

    def restart_ssh_service(self):
        self._run_command_without_raising(["systemctl", "restart", "sshd.service"], log_error=False)

    def stop_agent_service(self):
        self._run_command_without_raising(["systemctl", "stop", "{}.service".format(self.service_name)],
                                          log_error=False)

    def start_agent_service(self):
        self._run_command_without_raising(["systemctl", "start", "{}.service".format(self.service_name)],
                                          log_error=False)

    def register_agent_service(self):
        self._run_command_without_raising(["systemctl", "enable", "{}.service".format(self.service_name)],
                                          log_error=False)

    def unregister_agent_service(self):
        self._run_command_without_raising(["systemctl", "disable", "{}.service".format(self.service_name)],
                                          log_error=False)
