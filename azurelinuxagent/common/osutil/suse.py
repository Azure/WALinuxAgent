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

import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError # pylint: disable=W0611
from azurelinuxagent.common.future import ustr # pylint: disable=W0611
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

    def set_hostname(self, hostname):
        self._run_command_without_raising(["hostnamectl", "set-hostname", hostname], log_error=False)

    def stop_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "stop", "{}.service".format(self.dhclient_name)],
                                          log_error=False)

    def start_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "start", "{}.service".format(self.dhclient_name)],
                                          log_error=False)

    def start_network(self) :
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
