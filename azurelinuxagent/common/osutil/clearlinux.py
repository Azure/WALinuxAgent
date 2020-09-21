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

import os # pylint: disable=W0611
import re # pylint: disable=W0611
import pwd # pylint: disable=W0611
import shutil # pylint: disable=W0611
import socket # pylint: disable=W0611
import array # pylint: disable=W0611
import struct # pylint: disable=W0611
import fcntl # pylint: disable=W0611
import time # pylint: disable=W0611
import base64 # pylint: disable=W0611
import errno
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger # pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.exception import OSUtilError

class ClearLinuxUtil(DefaultOSUtil):

    def __init__(self):
        super(ClearLinuxUtil, self).__init__()
        self.agent_conf_file_path = '/usr/share/defaults/waagent/waagent.conf'
        self.jit_enabled = True

    def is_dhcp_enabled(self):
        return True

    def start_network(self) :
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is socket activated. No need to restart it.
        pass

    def stop_dhcp_service(self):
        return shellutil.run("systemctl stop systemd-networkd", chk_err=False)

    def start_dhcp_service(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("systemctl start {0}".format(self.service_name), chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("systemctl stop {0}".format(self.service_name), chk_err=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "systemd-networkd"])

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
                    raise IOError(errno.ENOENT, "Empty File", passwd_file_path)
            except (IOError, OSError) as file_read_err:
                if file_read_err.errno != errno.ENOENT:
                    raise
                new_passwd = ["root:*LOCK*:14600::::::"]
            else:
                passwd = passwd_content.split('\n')
                new_passwd = [x for x in passwd if not x.startswith("root:")]
                new_passwd.insert(0, "root:*LOCK*:14600::::::")
            fileutil.write_file(passwd_file_path, "\n".join(new_passwd))
        except IOError as e: # pylint: disable=C0103
            raise OSUtilError("Failed to delete root password:{0}".format(e))
        pass # pylint: disable=W0107
