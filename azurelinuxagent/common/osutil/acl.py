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
# Azure Container Linux (ACL) is an immutable, sysext-based distro derived
# from Flatcar.  This osutil is a standalone copy of MarinerOSUtil with
# ACL-specific overrides so that future Azure-Linux changes do not
# inadvertently affect the immutable ACL image.
#

import time

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.utils.shellutil import CommandError


class AclOSUtil(DefaultOSUtil):
    def __init__(self):
        super(AclOSUtil, self).__init__()
        self.jit_enabled = True

    @staticmethod
    def get_systemd_unit_file_install_path():
        # ACL delivers waagent as a sysext; /usr is read-only.
        # Writable systemd units must go to /etc/systemd/system.
        return "/etc/systemd/system"

    @staticmethod
    def get_agent_bin_path():
        return "/usr/bin"

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        self._run_command_without_raising(["systemctl", "start", "systemd-networkd"], log_error=False)

    def restart_if(self, ifname, retries=3, wait=5):
        """
        Restart an interface by bouncing the link. systemd-networkd observes
        this event, and forces a renew of DHCP.
        """
        for attempt in range(1, retries + 1):
            try:
                shellutil.run_command(["ip", "link", "set", ifname, "down"])
                shellutil.run_command(["ip", "link", "set", ifname, "up"])
                return
            except CommandError as e:
                logger.warn("failed to restart {0}: {1}".format(ifname, e))
                if attempt < retries:
                    logger.info("retrying in {0} seconds".format(wait))
                    time.sleep(wait)
        logger.warn("exceeded restart retries for {0}".format(ifname))

    def restart_ssh_service(self):
        # ACL uses sshd.socket for socket-activated SSH (similar to
        # Flatcar/CoreOS).  Restarting sshd.service would conflict with
        # the active sshd.socket.
        pass

    def stop_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "stop", "systemd-networkd"], log_error=False)

    def start_dhcp_service(self):
        self._run_command_without_raising(["systemctl", "start", "systemd-networkd"], log_error=False)

    def start_agent_service(self):
        self._run_command_without_raising(["systemctl", "start", "{0}".format(self.service_name)], log_error=False)

    def stop_agent_service(self):
        self._run_command_without_raising(["systemctl", "stop", "{0}".format(self.service_name)], log_error=False)

    def register_agent_service(self):
        self._run_command_without_raising(["systemctl", "enable", "{0}".format(self.service_name)], log_error=False)

    def unregister_agent_service(self):
        self._run_command_without_raising(["systemctl", "disable", "{0}".format(self.service_name)], log_error=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "systemd-networkd"])

    def conf_sshd(self, disable_password):
        pass
