# Compose Content for: L2-platform/distribution-os-adapters.md

Total files: 13

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.get_dhcp_pid`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.get_dhcp_pid.self`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._get_dhcp_pid`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.set_ssh_client_alive_interval`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.set_ssh_client_alive_interval.self`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil.conf_sshd`
- `%REPO%/azurelinuxagent/commo

### Source excerpt

````
# Microsoft Azure Linux Agent
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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class AlpineOSUtil(DefaultOSUtil):

    def __init__(self):
        super(AlpineOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.jit_enabled = True

    def is_dhcp_enabled(self):
        return True

    def get_dhcp_pid(self):
        return sorted(self._get_dhcp_pid(["pidof", "dhcpcd"]))

    # TODO: We really should get the pid from `dhcpcd --printpidfile`
    def restart_if(self, ifname, retries=None, wait=None):
        logger.info('restarting {} (sort of, actually SIGHUPing dhcpcd)'.format(ifname))
        pid = self.get_dhcp_pid()[0]
        if pid != None:
            ret = shellutil.run_get_output('kill -HUP {}'.format(pid))  # pylint: disable=W0612

    def set_ssh_client_alive_interval(self):
        # Alpine will handle this.
        pass

    def conf_sshd(self, disable_password):
        # Alpine will handle this.
        pass

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.stop_dhcp_service`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil.stop_dhcp_service.self`
- `%REPO%/azurelinux

### Source excerpt

````
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

import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class ArchUtil(DefaultOSUtil):
    def __init__(self):
        super(ArchUtil, self).__init__()
        self.jit_enabled = True

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    @staticmethod
    def get_agent_bin_path():
        return "/usr/bin"

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is socket activated on CoreOS.  No need to restart it.
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

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil.get_service_name`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.is_dhcp_available`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.is_dhcp_available.self`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osuti

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2025 Chainguard Inc
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
import glob
import textwrap
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class ChainguardOSUtil(DefaultOSUtil):

    def __init__(self):
        super(ChainguardOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.jit_enabled = True
        self.__name__ = 'Chainguard'
        self.service_name = self.get_service_name()

    @staticmethod
    def get_agent_bin_path():
        return "/usr/bin"

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    def restart_if(self, ifname, retries=3, wait=5):
        """
        Restart systemd-networkd
        """
        retry_limit=retries+1
        for attempt in range(1, retry_limit):
            try:
                shellutil.run_command(["systemctl", "restart", "systemd-networkd"])

            except shellutil.CommandError as cmd_err:
                logger.warn("failed to restart systemd-networkd: return code {1}".format(cmd_err.returncode))
                if attempt < retry_limit:
                    logger.info("retrying in {0} seconds".format(wait))
                    time.sleep(wait)
                else:
                    logger.warn("exceeded restart retries")

    def is_dhcp_available(self):
        return True

    def is_dhcp_enabled(self):
        return shellutil.run("systemctl is-enabled sy
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil.restart_ssh_service`
- `%REPO%/azurelinuxa

### Source excerpt

````
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

import os  # pylint: disable=W0611
import re  # pylint: disable=W0611
import pwd  # pylint: disable=W0611
import shutil  # pylint: disable=W0611
import socket  # pylint: disable=W0611
import array  # pylint: disable=W0611
import struct  # pylint: disable=W0611
import fcntl  # pylint: disable=W0611
import time  # pylint: disable=W0611
import base64  # pylint: disable=W0611
import errno
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger  # pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil  # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.exception import OSUtilError

class ClearLinuxUtil(DefaultOSUtil):

    def __init__(self):
        super(ClearLinuxUtil, self).__init__()
        self.agent_conf_file_path = '/usr/share/defaults/waagent/waagent.conf'
        self.jit_enabled = True

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    @staticmethod
    def get_agent_bin_path():
        return "/usr/bin"

    def is_dhcp_enabled(self):
        return True

    def start_network(self) :
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is soc
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.is_sys_user`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.is_sys_user.self`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.is_sys_user.username`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil.

### Source excerpt

````
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

import os
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class CoreOSUtil(DefaultOSUtil):

    def __init__(self):
        super(CoreOSUtil, self).__init__()
        self.agent_conf_file_path = '/usr/share/oem/waagent.conf'
        self.waagent_path = '/usr/share/oem/bin/waagent'
        self.python_path = '/usr/share/oem/python/bin'
        self.jit_enabled = True
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

    @staticmethod
    def get_agent_bin_path():
        return "/usr/share/oem/bin"

    def is_sys_user(self, username):
        # User 'core' is not a sysuser.
        if username == 'core':
            return False
        return super(CoreOSUtil, self).is_sys_user(username)

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        shellutil.run("systemctl restart systemd-networkd")

    def restart_ssh_service(self):
        # SSH is socket activated on CoreOS.  No need to restart it.
        pass


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.stop_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.stop_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.start_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.remove_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.remove_rules_files.self`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.remove_rules_files.rules_files`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.restore_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil.restore

### Source excerpt

````
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

import os  # pylint: disable=W0611
import re  # pylint: disable=W0611
import pwd  # pylint: disable=W0611
import shutil  # pylint: disable=W0611
import socket  # pylint: disable=W0611
import array  # pylint: disable=W0611
import struct  # pylint: disable=W0611
import fcntl  # pylint: disable=W0611
import time  # pylint: disable=W0611
import base64  # pylint: disable=W0611
import azurelinuxagent.common.logger as logger  # pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil  # pylint: disable=W0611
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil  # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class DebianOSBaseUtil(DefaultOSUtil):

    def __init__(self):
        super(DebianOSBaseUtil, self).__init__()
        self.jit_enabled = True

    def restart_ssh_service(self):
        return shellutil.run("systemctl --job-mode=ignore-dependencies try-reload-or-restart ssh", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("service azurelinuxagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("service azurelinuxagent start", chk_err=False)

    def start_network(self):
        pass

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')


class DebianOS
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.stop_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.stop_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.start_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.remove_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.remove_rules_files.self`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.remove_rules_files.rules_files`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.restore_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil.restore_rules_files.se

### Source excerpt

````
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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class DevuanOSUtil(DefaultOSUtil):

    def __init__(self):
        super(DevuanOSUtil, self).__init__()
        self.jit_enabled = True

    def restart_ssh_service(self):
        logger.info("DevuanOSUtil::restart_ssh_service - trying to restart sshd")
        return shellutil.run("/usr/sbin/service restart ssh", chk_err=False)

    def stop_agent_service(self):
        logger.info("DevuanOSUtil::stop_agent_service - trying to stop waagent")
        return shellutil.run("/usr/sbin/service walinuxagent stop", chk_err=False)

    def start_agent_service(self):
        logger.info("DevuanOSUtil::start_agent_service - trying to start waagent")
        return shellutil.run("/usr/sbin/service walinuxagent start", chk_err=False)

    def start_network(self):
        pass

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/fedora.py.FedoraOSUtil.restart_s

### Source excerpt

````
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
        return shellutil.ru
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/default.py.PRODUCT_ID_FILE`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DMIDECODE_CMD`
- `%REPO%/azurelinuxagent/common/osutil/default.py.UUID_PATTERN`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.set_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.set_hostname.hostname`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.publish_hostname`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.publish_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.publish_hostname.hostname`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.publish_hostname.recover_nic`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil.register_agent_service`
- `%REPO%/azu

### Source excerpt

````
# Microsoft Azure Linux Agent
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

import os

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil, PRODUCT_ID_FILE, DMIDECODE_CMD, UUID_PATTERN
from azurelinuxagent.common.utils import textutil, fileutil  # pylint: disable=W0611

# pylint: disable=W0105
'''
The IOSXE distribution is a variant of the Centos distribution,
version 7.1.
The primary difference is that IOSXE makes some assumptions about
the waagent environment:
 - only the waagent daemon is executed
 - no provisioning is performed
 - no DHCP-based services are available
'''
# pylint: enable=W0105

class IosxeOSUtil(DefaultOSUtil):
    def __init__(self):  # pylint: disable=W0235
        super(IosxeOSUtil, self).__init__()

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    def set_hostname(self, hostname):
        """
        Unlike redhat 6.x, redhat 7.x will set hostname via hostnamectl
        Due to a bug in systemd in Centos-7.0, if this call fails, fallback
        to hostname.
        """
        hostnamectl_cmd = ["hostnamectl", "set-hostname", hostname, "--static"]
        try:
            shellutil.run_command(hostnamectl_cmd)
        except Exception as e:
            logger.warn("[{0}] failed with error: {1}, attempting fallback".format(' '.join(hostnamectl_cmd), ustr(e)))
            DefaultOSUtil.set_hostname(self, hostname)

    def publish_hostname(s
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_without_raising`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil.restart_ssh_service.self`
- `%REPO%/a

### Source excerpt

````
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

from azurelinuxagent.common.osutil.default import DefaultOSUtil


class MarinerOSUtil(DefaultOSUtil):
    def __init__(self):
        super(MarinerOSUtil, self).__init__()
        self.jit_enabled = True

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    @staticmethod
    def get_agent_bin_path():
        return "/usr/bin"

    def is_dhcp_enabled(self):
        return True

    def start_network(self):
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


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/utils/networkutil.py.NetworkInterfaceCard`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil._ip_command_output`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.eject_dvd`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.eject_dvd.self`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.eject_dvd.chk_err`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.useradd`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.useradd.self`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.useradd.username`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.useradd.expiration`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.useradd.comment`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil.get_userentry`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_raising_OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil.get_dhcp_pid`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.O

### Source excerpt

````
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
        self.jit_enabled = True

    _ip_command_output = re.compile(r'^\d+:\s+(\w+):\s+(.*)$')

    def eject_dvd(self, chk_err=True):
        logger.warn('eject is not supported on OpenWRT')

    def useradd(self, username, expiration=None, comment=None):
        """
        Create user account with 'username'
        """
        userentry = self.get_userentry(username)
        if userentry is not None:
            logger.info("User {0} already exists, skip useradd", username)
            return

        if expiration is not None:
            cmd = ["useradd", "-m", username, "-s", "/bin/ash", "-e", expiration]
        else:
            cmd = ["useradd", "-m", username, "-s", "/bin/ash"]

        if not os.path.exists("/home"):
            os.mkdir("/home")

        if comment is not None:
            cmd.extend(["-c", comment])
        self._run_command_raising_OSUtilError(cmd, err_msg="Failed to create u
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.get_systemd_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_if`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_if.self`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_if.ifname`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_if.retries`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_if.wait`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/photonos.py.PhotonOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/osutil/photonos.

### Source excerpt

````
#
# Copyright 2021 Microsoft Corporation
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

import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class PhotonOSUtil(DefaultOSUtil):

    def __init__(self):
        super(PhotonOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'

    @staticmethod
    def get_systemd_unit_file_install_path():
        return '/usr/lib/systemd/system'

    @staticmethod
    def get_agent_bin_path():
        return '/usr/bin'

    def is_dhcp_enabled(self):
        return True

    def start_network(self) :
        return shellutil.run('systemctl start systemd-networkd', chk_err=False)

    def restart_if(self, ifname=None, retries=None, wait=None):
        shellutil.run('systemctl restart systemd-networkd')

    def restart_ssh_service(self):
        shellutil.run('systemctl restart sshd')

    def stop_dhcp_service(self):
        return shellutil.run('systemctl stop systemd-networkd', chk_err=False)

    def start_dhcp_service(self):
        return shellutil.run('systemctl start systemd-networkd', chk_err=False)

    def start_agent_service(self):
        return shellutil.run('systemctl start waagent', chk_err=False)

    def stop_agent_service(self):
        return shellutil.run('systemctl stop waagent', chk_err=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(['pidof', 'systemd-networkd'])

    def conf_sshd(self, disable_password):
        pass

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.get_service_name`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.stop_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.stop_agent_service.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.start_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.remove_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.remove_rules_files.self`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.remove_rules_files.rules_files`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.restore_rules_files`
- `%REPO%/azurelinuxagent/common/osutil/ubuntu.py.Ubuntu14OSUtil.restore_rules_files.self`
- `%REPO%/azurelinuxagent/common/osutil/ub

### Source excerpt

````
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

import glob
import textwrap
import time

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.osutil.default import DefaultOSUtil


class Ubuntu14OSUtil(DefaultOSUtil):

    def __init__(self):
        super(Ubuntu14OSUtil, self).__init__()
        self.jit_enabled = True
        self.service_name = self.get_service_name()

    @staticmethod
    def get_service_name():
        return "walinuxagent"

    def start_network(self):
        return shellutil.run("service networking start", chk_err=False)

    def stop_agent_service(self):
        try:
            shellutil.run_command(["service", self.service_name, "stop"])
        except shellutil.CommandError as cmd_err:
            return cmd_err.returncode
        return 0

    def start_agent_service(self):
        try:
            shellutil.run_command(["service", self.service_name, "start"])
        except shellutil.CommandError as cmd_err:
            return cmd_err.returncode
        return 0

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')


class Ubuntu12OSUtil(Ubuntu14OSUtil):
    def __init__(self):  # pylint: disable=W0235
        super(Ubuntu12OSUtil, self).__init__()

    # Override
    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "dhclient3"])


class Ubuntu16OSUtil(Ubuntu14OSU
````

---
