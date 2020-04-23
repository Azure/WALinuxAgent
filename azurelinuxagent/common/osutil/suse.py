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
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class SUSE11OSUtil(DefaultOSUtil):
    def __init__(self):
        super(SUSE11OSUtil, self).__init__()
        self.jit_enabled = True
        self.dhclient_name='dhcpcd'

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/HOSTNAME', hostname)
        try: 
            shellutil.run_command(["hostname", hostname])
        except Exception as e:
            raise OSUtilError(
                "Failed to set hostname. Error: {}".format(ustr(e))
            )

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", self.dhclient_name])

    def is_dhcp_enabled(self):
        return True

    def stop_dhcp_service(self):
        try:
            shellutil.run_command(
                ["/sbin/service", self.dhclient_name, "stop"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to stop dhcp client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def start_dhcp_service(self):
        try:
            shellutil.run_command(
                ["/sbin/service", self.dhclient_name, "start"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start dhcp client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def start_network(self) :
        try:
            shellutil.run_command(
                ["/sbin/service", "network", "start"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start network client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def restart_ssh_service(self):
        try:
            shellutil.run_command(
                ["/sbin/service", "sshd", "restart"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to restart sshd client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def stop_agent_service(self):
        try:
            shellutil.run_command(
                ["/sbin/service", self.service_name, "stop"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to stop {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def start_agent_service(self):
        try:
            shellutil.run_command(
                ["/sbin/service", self.service_name, "start"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def register_agent_service(self):
        try:
            shellutil.run_command(
                ["/sbin/insserv", self.service_name]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to enable {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def unregister_agent_service(self):
        try:
            shellutil.run_command(
                ["/sbin/insserv", "-r", self.service_name]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to remove {}. Error {}".format(
                    self.service_name, ustr(e))
            )


class SUSEOSUtil(SUSE11OSUtil):
    def __init__(self):
        super(SUSEOSUtil, self).__init__()
        self.dhclient_name = 'wickedd-dhcp4'

    def set_hostname(self, hostname):
        try: 
            shellutil.run_command(["hostnamectl", "set-hostname", hostname])
        except Exception as e:
            raise OSUtilError(
                "Failed to set hostname. Error: {}".format(ustr(e))
            )

    def stop_dhcp_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "stop", "{}.service".format(self.dhclient_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to stop dhcp client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def start_dhcp_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "start", "{}.service".format(self.dhclient_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start dhcp client {}. Error {}".format(
                    self.dhclient_name, ustr(e))
                )

    def start_network(self) :
        try:
            shellutil.run_command(
                ["systemctl", "start", "network.service"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start network. Error: {}".format(ustr(e))
            )

    def restart_ssh_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "restart", "sshd.service"]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to restart sshd. Error: {}".format(ustr(e))
            )

    def stop_agent_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "stop", "{}.service".format(self.service_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to stop {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def start_agent_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "start", "{}.service".format(self.service_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to start {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def register_agent_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "enable", "{}.service".format(self.service_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to enable {}. Error {}".format(
                    self.service_name, ustr(e))
            )

    def unregister_agent_service(self):
        try:
            shellutil.run_command(
                ["systemctl", "disable", "{}.service".format(self.service_name)]
            )
        except Exception as e:
            raise OSUtilError(
                "Failed to disable {}. Error {}".format(
                    self.service_name, ustr(e))
            )

