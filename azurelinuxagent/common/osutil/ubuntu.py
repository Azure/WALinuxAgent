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

import time
import os

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.utils import fileutil


class Ubuntu14OSUtil(DefaultOSUtil):
    def __init__(self):
        super(Ubuntu14OSUtil, self).__init__()

    def start_network(self):
        return shellutil.run("service networking start", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("service walinuxagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("service walinuxagent start", chk_err=False)

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')

    def mount_cgroups(self):
        try:
            if not os.path.exists('/sys/fs/cgroup'):
                fileutil.mkdir('/sys/fs/cgroup')
                self.mount(device='cgroup_root',
                           mount_point='/sys/fs/cgroup',
                           option="-t tmpfs",
                           chk_err=False)
            elif not os.path.isdir('/sys/fs/cgroup'):
                logger.error("Count not mount cgroups: ordinary file at /sys/fs/cgroup")
                return

            if not os.path.exists('/sys/fs/cgroup/cpu,cpuacct'):
                fileutil.mkdir('/sys/fs/cgroup/cpu,cpuacct')
                self.mount(device='cpu,cpuacct',
                           mount_point='/sys/fs/cgroup/cpu,cpuacct/',
                           option="-t cgroup -o cpu,cpuacct",
                           chk_err=False)

            if not os.path.exists('/sys/fs/cgroup/cpu'):
                os.symlink('/sys/fs/cgroup/cpu,cpuacct/', '/sys/fs/cgroup/cpu')

            if not os.path.exists('/sys/fs/cgroup/memory'):
                fileutil.mkdir('/sys/fs/cgroup/memory')
                self.mount(device='memory',
                           mount_point='/sys/fs/cgroup/memory/',
                           option="-t cgroup -o memory",
                           chk_err=False)
        except Exception as e:
            logger.error("Could not mount cgroups: {0}", ustr(e))


class Ubuntu12OSUtil(Ubuntu14OSUtil):
    def __init__(self):
        super(Ubuntu12OSUtil, self).__init__()

    # Override
    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pidof dhclient3", chk_err=False)
        return ret[1] if ret[0] == 0 else None

    def mount_cgroups(self):
        pass


class Ubuntu16OSUtil(Ubuntu14OSUtil):
    """
    Ubuntu 16.04, 16.10, and 17.04.
    """
    def __init__(self):
        super(Ubuntu16OSUtil, self).__init__()

    def register_agent_service(self):
        return shellutil.run("systemctl unmask walinuxagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl mask walinuxagent", chk_err=False)

    def mount_cgroups(self):
        pass


class Ubuntu18OSUtil(Ubuntu16OSUtil):
    """
    Ubuntu 18.04
    """
    def __init__(self):
        super(Ubuntu18OSUtil, self).__init__()

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pidof systemd-networkd")
        return ret[1] if ret[0] == 0 else None

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def stop_network(self):
        return shellutil.run("systemctl stop systemd-networkd", chk_err=False)

    def start_dhcp_service(self):
        return self.start_network()

    def stop_dhcp_service(self):
        return self.stop_network()

    def start_agent_service(self):
        return shellutil.run("systemctl start walinuxagent", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("systemctl stop walinuxagent", chk_err=False)


class UbuntuOSUtil(Ubuntu16OSUtil):
    def __init__(self):
        super(UbuntuOSUtil, self).__init__()

    def restart_if(self, ifname, retries=3, wait=5):
        """
        Restart an interface by bouncing the link. systemd-networkd observes
        this event, and forces a renew of DHCP.
        """
        retry_limit=retries+1
        for attempt in range(1, retry_limit):
            return_code=shellutil.run("ip link set {0} down && ip link set {0} up".format(ifname))
            if return_code == 0:
                return
            logger.warn("failed to restart {0}: return code {1}".format(ifname, return_code))
            if attempt < retry_limit:
                logger.info("retrying in {0} seconds".format(wait))
                time.sleep(wait)
            else:
                logger.warn("exceeded restart retries")

    def mount_cgroups(self):
        pass


class UbuntuSnappyOSUtil(Ubuntu14OSUtil):
    def __init__(self):
        super(UbuntuSnappyOSUtil, self).__init__()
        self.conf_file_path = '/apps/walinuxagent/current/waagent.conf'

    def mount_cgroups(self):
        pass
