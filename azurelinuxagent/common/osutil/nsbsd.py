#
# Copyright 2018 Stormshield
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

import os

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil


class NSBSDOSUtil(FreeBSDOSUtil):
    resolver = None

    def __init__(self):
        super(NSBSDOSUtil, self).__init__()

        if self.resolver is None:
            # NSBSD doesn't have a system resolver, configure a python one

            try:
                import dns.resolver
            except ImportError:
                raise OSUtilError("Python DNS resolver not available. Cannot proceed!")

            self.resolver = dns.resolver.Resolver(configure=False)
            servers = []
            cmd = "getconf /usr/Firewall/ConfigFiles/dns Servers | tail -n +2"
            ret, output = shellutil.run_get_output(cmd)  # pylint: disable=W0612
            for server in output.split("\n"):
                if server == '':
                    break
                server = server[:-1]  # remove last '='
                cmd = "grep '{}' /etc/hosts".format(server) + " | awk '{print $1}'"
                ret, ip = shellutil.run_get_output(cmd)
                ip = ip.strip() # Remove new line char
                servers.append(ip)
            self.resolver.nameservers = servers
            dns.resolver.override_system_resolver(self.resolver)

    def set_hostname(self, hostname):
        self._run_command_without_raising(
            ['/usr/Firewall/sbin/setconf', '/usr/Firewall/System/global', 'SystemName', hostname])
        self._run_command_without_raising(["/usr/Firewall/sbin/enlog"])
        self._run_command_without_raising(["/usr/Firewall/sbin/enproxy", "-u"])
        self._run_command_without_raising(["/usr/Firewall/sbin/ensl", "-u"])
        self._run_command_without_raising(["/usr/Firewall/sbin/ennetwork", "-f"])

    def restart_ssh_service(self):
        return shellutil.run('/usr/Firewall/sbin/enservice', chk_err=False)

    def conf_sshd(self, disable_password):
        option = "0" if disable_password else "1"

        shellutil.run('setconf /usr/Firewall/ConfigFiles/system SSH State 1',
                      chk_err=False)
        shellutil.run('setconf /usr/Firewall/ConfigFiles/system SSH Password {}'.format(option),
                      chk_err=False)
        shellutil.run('enservice', chk_err=False)

        logger.info("{0} SSH password-based authentication methods."
                    .format("Disabled" if disable_password else "Enabled"))

    def useradd(self, username, expiration=None, comment=None):
        """
        Create user account with 'username'
        """
        logger.warn("User creation disabled")

    def del_account(self, username):
        logger.warn("User deletion disabled")

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        logger.warn("Sudo is not enabled")

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        self._run_command_raising_OSUtilError(["/usr/Firewall/sbin/fwpasswd", "-p", password],
                                              err_msg="Failed to set password for admin")

        # password set, activate webadmin and ssh access
        commands = [['setconf', '/usr/Firewall/ConfigFiles/webadmin', 'ACL', 'any'], ['ensl']]
        self._run_multiple_commands_without_raising(commands, log_error=False, continue_on_error=False)

    def deploy_ssh_pubkey(self, username, pubkey):
        """
        Deploy authorized_key
        """
        path, thumbprint, value = pubkey  # pylint: disable=W0612

        # overide parameters
        super(NSBSDOSUtil, self).deploy_ssh_pubkey('admin',
                                                   ["/usr/Firewall/.ssh/authorized_keys", thumbprint, value])

    def del_root_password(self):
        logger.warn("Root password deletion disabled")

    def start_dhcp_service(self):
        shellutil.run("/usr/Firewall/sbin/nstart dhclient", chk_err=False)

    def stop_dhcp_service(self):
        shellutil.run("/usr/Firewall/sbin/nstop dhclient", chk_err=False)

    def get_dhcp_pid(self):
        ret = ""
        pidfile = "/var/run/dhclient.pid"

        if os.path.isfile(pidfile):
            ret = fileutil.read_file(pidfile, encoding='ascii')
        return self._text_to_pid_list(ret)

    def eject_dvd(self, chk_err=True):
        pass

    def restart_if(self, ifname=None, retries=None, wait=None):
        # Restart dhclient only to publish hostname
        shellutil.run("ennetwork", chk_err=False)

    def set_dhcp_hostname(self, hostname):
        # already done by the dhcp client
        pass

    def get_firewall_dropped_packets(self, dst_ip=None):
        # disable iptables methods
        return 0

    def get_firewall_will_wait(self):
        # disable iptables methods
        return ""

    def _delete_rule(self, rule):
        # disable iptables methods
        return

    def remove_firewall(self, dst_ip=None, uid=None, wait=""):
        # disable iptables methods
        return True

    def enable_firewall(self, dst_ip=None, uid=None):
        # disable iptables methods
        return True, True

    def get_firewall_list(self, wait=""):
        # disable iptables methods
        return ""
