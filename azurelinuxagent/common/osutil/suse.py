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
import re
import pwd
import shutil
import socket
import array
import struct
import fcntl
import time
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class SUSE11OSUtil(DefaultOSUtil):
    def __init__(self):
        super(SUSE11OSUtil, self).__init__()
        self.dhclient_name='dhcpcd'

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/HOSTNAME', hostname)
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pidof {0}".format(self.dhclient_name),
                                       chk_err=False)
        return ret[1] if ret[0] == 0 else None

    def is_dhcp_enabled(self):
        return True

    def stop_dhcp_service(self):
        cmd = "/sbin/service {0} stop".format(self.dhclient_name)
        return shellutil.run(cmd, chk_err=False)

    def start_dhcp_service(self):
        cmd = "/sbin/service {0} start".format(self.dhclient_name)
        return shellutil.run(cmd, chk_err=False)

    def start_network(self) :
        return shellutil.run("/sbin/service start network", chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run("/sbin/service sshd restart", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("/sbin/service waagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("/sbin/service waagent start", chk_err=False)

    def register_agent_service(self):
        return shellutil.run("/sbin/insserv waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("/sbin/insserv -r waagent", chk_err=False)

class SUSEOSUtil(SUSE11OSUtil):
    def __init__(self):
        super(SUSEOSUtil, self).__init__()
        self.dhclient_name = 'wickedd-dhcp4'

    def stop_dhcp_service(self):
        cmd = "systemctl stop {0}".format(self.dhclient_name)
        return shellutil.run(cmd, chk_err=False)

    def start_dhcp_service(self):
        cmd = "systemctl start {0}".format(self.dhclient_name)
        return shellutil.run(cmd, chk_err=False)

    def start_network(self) :
        return shellutil.run("systemctl start network", chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run("systemctl restart sshd", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("systemctl stop waagent", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("systemctl start waagent", chk_err=False)

    def register_agent_service(self):
        return shellutil.run("systemctl enable waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl disable waagent", chk_err=False)


