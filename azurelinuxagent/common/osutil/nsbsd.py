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

import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil
import os

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

            self.resolver = dns.resolver.Resolver()
            servers = []
            cmd = "getconf /usr/Firewall/ConfigFiles/dns Servers | tail -n +2"
            ret, output = shellutil.run_get_output(cmd)
            for server in output.split("\n"):
                if server == '':
                    break
                server = server[:-1] # remove last '='
                cmd = "grep '{}' /etc/hosts".format(server) + " | awk '{print $1}'"
                ret, ip = shellutil.run_get_output(cmd)
                servers.append(ip)
            self.resolver.nameservers = servers
            dns.resolver.override_system_resolver(self.resolver)

    def set_hostname(self, hostname):
        shellutil.run("/usr/Firewall/sbin/setconf /usr/Firewall/System/global SystemName {0}".format(hostname))
        shellutil.run("/usr/Firewall/sbin/enlog")
        shellutil.run("/usr/Firewall/sbin/enproxy -u")
        shellutil.run("/usr/Firewall/sbin/ensl -u")
        shellutil.run("/usr/Firewall/sbin/ennetwork -f")

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

    def useradd(self, username, expiration=None):
        """
        Create user account with 'username'
        """
        logger.warn("User creation disabled")
        return

    def del_account(self, username):
        logger.warn("User deletion disabled")

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        logger.warn("Sudo is not enabled")

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        cmd = "/usr/Firewall/sbin/fwpasswd -p {0}".format(password)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for admin: {0}"
                               "").format(output))

        # password set, activate webadmin and ssh access
        shellutil.run('setconf /usr/Firewall/ConfigFiles/webadmin ACL any && ensl',
                      chk_err=False)

    def deploy_ssh_pubkey(self, username, pubkey):
        """
        Deploy authorized_key
        """
        path, thumbprint, value = pubkey

        #overide parameters
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

    def restart_if(self, ifname):
        # Restart dhclient only to publish hostname
        shellutil.run("ennetwork", chk_err=False)

    def set_dhcp_hostname(self, hostname):
        #already done by the dhcp client
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

    def remove_firewall(self, dst_ip=None, uid=None):
        # disable iptables methods
        return True

    def enable_firewall(self, dst_ip=None, uid=None):
        # disable iptables methods
        return True
