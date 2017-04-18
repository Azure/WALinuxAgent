#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import os
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class ArchUtil(DefaultOSUtil):
    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, iface):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is socket activated on CoreOS.  No need to restart it.
        pass

    def stop_dhcp_service(self):
        return shellutil.run("systemctl stop systemd-networkd", chk_err=False)

    def start_dhcp_service(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("systemctl start waagent", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("systemctl stop waagent", chk_err=False)

    def get_dhcp_pid(self):
        ret= shellutil.run_get_output("pidof systemd-networkd")
        return ret[1] if ret[0] == 0 else None

    def conf_sshd(self, disable_password):
        # Don't whack the system default sshd conf
        pass