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
import base64
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class ClearLinuxUtil(DefaultOSUtil):
    def __init__(self):
        super(ClearLinuxUtil, self).__init__()
        self.agent_conf_file_path = '/usr/share/defaults/waagent/waagent.conf'

    def is_dhcp_enabled(self):
        return True

    def start_network(self) :
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, iface):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is socket activated. No need to restart it.
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

    def del_root_password(self):
        try:
            passwd_file_path = conf.get_passwd_file_path()
            try:
                passwd_content = fileutil.read_file(passwd_file_path)
                if not passwd_content:
                    # Empty file is no better than no file
                    raise FileNotFoundError
            except FileNotFoundError:
                new_passwd = ["root:*LOCK*:14600::::::"]
            else:
                passwd = passwd_content.split('\n')
                new_passwd = [x for x in passwd if not x.startswith("root:")]
                new_passwd.insert(0, "root:*LOCK*:14600::::::")
            fileutil.write_file(passwd_file_path, "\n".join(new_passwd))
        except IOError as e:
            raise OSUtilError("Failed to delete root password:{0}".format(e))
        pass
