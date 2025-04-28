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
        return shellutil.run("systemctl is-enabled systemd-networkd", chk_err=False) == "enabled"

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "systemd-networkd"])

    def start_network(self):
        return shellutil.run("systemctl start systemd-networkd", chk_err=False)

    def stop_network(self):
        return shellutil.run("systemctl stop systemd-networkd", chk_err=False)

    def start_dhcp_service(self):
        return self.start_network()

    def stop_dhcp_service(self):
        return self.stop_network()

    def start_agent_service(self):
        return shellutil.run("systemctl start {0}".format(self.service_name), chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("systemctl stop {0}".format(self.service_name), chk_err=False)

    def get_dhcp_lease_endpoint(self):
        pathglob = "/run/systemd/netif/leases/*"
        logger.info("looking for leases in path [{0}]".format(pathglob))
        endpoint = None
        for lease_file in glob.glob(pathglob):
            try:
                with open(lease_file) as f:
                    lease = f.read()
                for line in lease.splitlines():
                    if line.startswith("OPTION_245"):
                        option_245 = line.split("=")[1]
                        options = [int(i, 16) for i in textwrap.wrap(option_245, 2)]
                        endpoint = "{0}.{1}.{2}.{3}".format(*options)
                        logger.info("found endpoint [{0}]".format(endpoint))
            except Exception as e:
                logger.info(
                    "Failed to parse {0}: {1}".format(lease_file, str(e))
                )
        if endpoint is not None:
            logger.info("cached endpoint found [{0}]".format(endpoint))
        else:
            logger.info("cached endpoint not found")
        return endpoint
