# Microsoft Azure Linux Agent
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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class AlpineOSUtil(DefaultOSUtil):
    def __init__(self):
        super(AlpineOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'

    def is_dhcp_enabled(self):
        return True

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output('pidof dhcpcd', chk_err=False)
        if ret[0] == 0:
            logger.info('dhcpcd is pid {}'.format(ret[1]))
            return ret[1].strip()
        return None

    def restart_if(self, ifname):
        logger.info('restarting {} (sort of, actually SIGHUPing dhcpcd)'.format(ifname))
        pid = self.get_dhcp_pid()
        if pid != None:
            ret = shellutil.run_get_output('kill -HUP {}'.format(pid))

    def set_ssh_client_alive_interval(self):
        # Alpine will handle this.
        pass

    def conf_sshd(self, disable_password):
        # Alpine will handle this.
        pass
