#
# Copyright 2022 Red Hat Inc.
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
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class FedoraOSUtil(DefaultOSUtil):

    def __init__(self):
        super(FedoraOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'

    @staticmethod
    def get_systemd_unit_file_install_path():
        return '/usr/lib/systemd/system'

    @staticmethod
    def get_agent_bin_path():
        return '/usr/sbin'

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        pass

    def restart_if(self, ifname=None, retries=None, wait=None):
        retry_limit = retries+1
        for attempt in range(1, retry_limit):
            return_code = shellutil.run("ip link set {0} down && ip link set {0} up".format(ifname))
            if return_code == 0:
                return
            logger.warn("failed to restart {0}: return code {1}".format(ifname, return_code))
            if attempt < retry_limit:
                logger.info("retrying in {0} seconds".format(wait))
                time.sleep(wait)
            else:
                logger.warn("exceeded restart retries")

    def restart_ssh_service(self):
        shellutil.run('systemctl restart sshd')

    def stop_dhcp_service(self):
        pass

    def start_dhcp_service(self):
        pass

    def start_agent_service(self):
        return shellutil.run('systemctl start waagent', chk_err=False)

    def stop_agent_service(self):
        return shellutil.run('systemctl stop waagent', chk_err=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "dhclient"])

    def conf_sshd(self, disable_password):
        pass
