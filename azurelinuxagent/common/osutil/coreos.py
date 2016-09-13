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

class CoreOSUtil(DefaultOSUtil):
    def __init__(self):
        super(CoreOSUtil, self).__init__()
        self.agent_conf_file_path = '/usr/share/oem/waagent.conf'
        self.waagent_path = '/usr/share/oem/bin/waagent'
        self.python_path = '/usr/share/oem/python/bin'
        if 'PATH' in os.environ:
            path = "{0}:{1}".format(os.environ['PATH'], self.python_path)
        else:
            path = self.python_path
        os.environ['PATH'] = path

        if 'PYTHONPATH' in os.environ:
            py_path = os.environ['PYTHONPATH']
            py_path = "{0}:{1}".format(py_path, self.waagent_path)
        else:
            py_path = self.waagent_path
        os.environ['PYTHONPATH'] = py_path

    def is_sys_user(self, username):
        # User 'core' is not a sysuser.
        if username == 'core':
            return False
        return super(CoreOSUtil, self).is_sys_user(username)

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, *dummy, **_):
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
        ret = shellutil.run_get_output("systemctl show -p MainPID "
                                       "systemd-networkd", chk_err=False)
        pid = ret[1].split('=', 1)[-1].strip() if ret[0] == 0 else None
        return pid if pid != '0' else None

    def conf_sshd(self, disable_password):
        # In CoreOS, /etc/sshd_config is mount readonly.  Skip the setting.
        pass
