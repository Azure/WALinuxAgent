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
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr, bytebuffer # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError, CryptError
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil # pylint: disable=W0611
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class Redhat6xOSUtil(DefaultOSUtil):

    def __init__(self):
        super(Redhat6xOSUtil, self).__init__()
        self.jit_enabled = True

    def start_network(self):
        return shellutil.run("/sbin/service networking start", chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run("/sbin/service sshd condrestart", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("/sbin/service {0} stop".format(self.service_name), chk_err=False)

    def start_agent_service(self):
        return shellutil.run("/sbin/service {0} start".format(self.service_name), chk_err=False)

    def register_agent_service(self):
        return shellutil.run("chkconfig --add {0}".format(self.service_name), chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("chkconfig --del {0}".format(self.service_name), chk_err=False)

    def openssl_to_openssh(self, input_file, output_file):
        pubkey = fileutil.read_file(input_file)
        try:
            cryptutil = CryptUtil(conf.get_openssl_cmd())
            ssh_rsa_pubkey = cryptutil.asn1_to_ssh(pubkey)
        except CryptError as e: # pylint: disable=C0103
            raise OSUtilError(ustr(e))
        fileutil.append_file(output_file, ssh_rsa_pubkey)

    # Override
    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "dhclient"])

    def set_hostname(self, hostname):
        """
        Set /etc/sysconfig/network
        """
        fileutil.update_conf_file('/etc/sysconfig/network',
                                  'HOSTNAME',
                                  'HOSTNAME={0}'.format(hostname))
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def set_dhcp_hostname(self, hostname):
        ifname = self.get_if_name()
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        fileutil.update_conf_file(filepath,
                                  'DHCP_HOSTNAME',
                                  'DHCP_HOSTNAME={0}'.format(hostname))

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhclient/dhclient-*.leases')


class RedhatOSUtil(Redhat6xOSUtil):
    def __init__(self):
        super(RedhatOSUtil, self).__init__()
        self.service_name = self.get_service_name()

    def set_hostname(self, hostname):
        """
        Unlike redhat 6.x, redhat 7.x will set hostname via hostnamectl
        Due to a bug in systemd in Centos-7.0, if this call fails, fallback
        to hostname.
        """
        hostnamectl_cmd = ['hostnamectl', 'set-hostname', hostname, '--static']
        if self._run_command_without_raising(hostnamectl_cmd, log_error=False) != 0:
            logger.warn("[{0}] failed, attempting fallback".format(' '.join(hostnamectl_cmd)))
            DefaultOSUtil.set_hostname(self, hostname)

    def publish_hostname(self, hostname):
        """
        Restart NetworkManager first before publishing hostname
        """
        shellutil.run("service NetworkManager restart")
        super(RedhatOSUtil, self).publish_hostname(hostname)

    def register_agent_service(self):
        return shellutil.run("systemctl enable {0}".format(self.service_name), chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl disable {0}".format(self.service_name), chk_err=False)

    def openssl_to_openssh(self, input_file, output_file):
        DefaultOSUtil.openssl_to_openssh(self, input_file, output_file)

    def get_dhcp_lease_endpoint(self):
        # dhclient
        endpoint = self.get_endpoint_from_leases_path('/var/lib/dhclient/dhclient-*.lease')

        if endpoint is None:
            # NetworkManager
            endpoint = self.get_endpoint_from_leases_path('/var/lib/NetworkManager/dhclient-*.lease')

        return endpoint
