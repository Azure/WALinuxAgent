# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2018 Sonus Networks, Inc. (d.b.a. Ribbon Communications Operating Company)
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
import os
import re
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.utils.networkutil import NetworkInterfaceCard

class OpenWRTOSUtil(DefaultOSUtil):

    def __init__(self):
        super(OpenWRTOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.dhclient_name = 'udhcpc'
        self.ip_command_output = re.compile('^\d+:\s+(\w+):\s+(.*)$')
        self.jit_enabled = True
        
        
    def is_dhcp_enabled(self):
        pass

    def start_dhcp_service(self):
        pass

    def stop_dhcp_service(self):
        pass

    def start_network(self) :
        return shellutil.run("/etc/init.d/network start", chk_err=True)

    def restart_ssh_service(self):
        # Since Dropbear is the default ssh server on OpenWRt, lets do a sanity check
        if os.path.exists("/etc/init.d/sshd"):
            return shellutil.run("/etc/init.d/sshd restart", chk_err=True)
        else:
            logger.warn("sshd service does not exists", username)

    def stop_agent_service(self):
        return shellutil.run("/etc/init.d/waagent stop", chk_err=True)

    def start_agent_service(self):
        return shellutil.run("/etc/init.d/waagent start", chk_err=True)

    def register_agent_service(self):
        return shellutil.run("/etc/init.d/waagent enable", chk_err=True)

    def unregister_agent_service(self):
        return shellutil.run("/etc/init.d/waagent disable", chk_err=True)
