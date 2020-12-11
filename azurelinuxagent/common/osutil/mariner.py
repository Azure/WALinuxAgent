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

import errno
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.exception import OSUtilError

class MarinerOSUtil(DefaultOSUtil):
    def __init__(self):
        super(MarinerOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.jit_enabled = True

    def is_dhcp_enabled(self):
        return True

    def start_network(self) :
        self._run_command_without_raising(["systemctl", "start", "systemd-networkd"], log_error=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        self._run_command_without_raising(["systemctl", "restart", "systemd-networkd"])

    def restart_ssh_service(self):
        self._run_command_without_raising(["systemctl", "restart", "sshd"])

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
        except IOError as err:
            raise OSUtilError("Failed to delete root password:{0}".format(err))
