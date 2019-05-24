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
            cmd = "useradd -m {0} -s /bin/ash -e {1}".format(username, expiration)
        else:
            cmd = "useradd -m {0} -s /bin/ash".format(username)
        
        if not os.path.exists("/home"):
            os.mkdir("/home")

        if comment is not None:
            cmd += " -c {0}".format(comment)
        retcode, out = shellutil.run_get_output(cmd)
        if retcode != 0:
            raise OSUtilError(("Failed to create user account:{0}, "
                               "retcode:{1}, "
                               "output:{2}").format(username, retcode, out))

    def get_dhcp_pid(self):
        cmd = "pidof {0}".format(self.dhclient_name)
        ret= shellutil.run_get_output(cmd, chk_err=False)
        return ret[1] if ret[0] == 0 else None

    def get_nic_state(self):
        """
        Capture NIC state (IPv4 and IPv6 addresses plus link state).

        :return: Dictionary of NIC state objects, with the NIC name as key
        :rtype: dict(str,NetworkInformationCard)
        """
        state = {}
        status, output = shellutil.run_get_output("ip -o link", chk_err=False, log_cmd=False)

        if status != 0:
            logger.verbose("Could not fetch NIC link info; status {0}, {1}".format(status, output))
            return {}

        for entry in output.splitlines():
            result = self.ip_command_output.match(entry)
            if result:
                name = result.group(1)
                state[name] = NetworkInterfaceCard(name, result.group(2))


        self._update_nic_state(state, "ip -o -f inet address", NetworkInterfaceCard.add_ipv4, "an IPv4 address")
        self._update_nic_state(state, "ip -o -f inet6 address", NetworkInterfaceCard.add_ipv6, "an IPv6 address")

        return state

    def _update_nic_state(self, state, ip_command, handler, description):
        """
        Update the state of NICs based on the output of a specified ip subcommand.

        :param dict(str, NetworkInterfaceCard) state: Dictionary of NIC state objects
        :param str ip_command: The ip command to run
        :param handler: A method on the NetworkInterfaceCard class
        :param str description: Description of the particular information being added to the state
        """
        status, output = shellutil.run_get_output(ip_command, chk_err=True)
        if status != 0:
            return

        for entry in output.splitlines():
            result = self.ip_command_output.match(entry)
            if result:
                interface_name = result.group(1)
                if interface_name in state:
                    handler(state[interface_name], result.group(2))
                else:
                    logger.error("Interface {0} has {1} but no link state".format(interface_name, description))

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

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/hostname', hostname)
        shellutil.run("uci set system.@system[0].hostname='{0}' && uci commit system && /etc/init.d/system reload".format(hostname), chk_err=False)

    def remove_rules_files(self, rules_files=""):
        pass
