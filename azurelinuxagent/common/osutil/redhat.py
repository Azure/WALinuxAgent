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
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr, bytebuffer  # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError, CryptError
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil  # pylint: disable=W0611
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
        except CryptError as e:
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

    @staticmethod
    def get_systemd_unit_file_install_path():
        return "/usr/lib/systemd/system"

    def set_hostname(self, hostname):
        """
        Unlike redhat 6.x, redhat 7.x will set hostname via hostnamectl
        Due to a bug in systemd in Centos-7.0, if this call fails, fallback
        to hostname.
        """
        hostnamectl_cmd = ['hostnamectl', 'set-hostname', hostname, '--static']

        try:
            shellutil.run_command(hostnamectl_cmd, log_error=False)
        except shellutil.CommandError:
            logger.warn("[{0}] failed, attempting fallback".format(' '.join(hostnamectl_cmd)))
            DefaultOSUtil.set_hostname(self, hostname)

    def get_nm_controlled(self, ifname):
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        nm_controlled_cmd = ['grep', 'NM_CONTROLLED=', filepath]
        try:
            result = shellutil.run_command(nm_controlled_cmd, log_error=False).rstrip()

            if result and len(result.split('=')) > 1:
                # Remove trailing white space and ' or " characters
                value = result.split('=')[1].replace("'", '').replace('"', '').rstrip()
                if value == "n" or value == "no":
                    return False
        except shellutil.CommandError as e:
            # Command might fail because NM_CONTROLLED value is not in interface config file (exit code 1).
            # Log warning for any other exit code.
            # NM_CONTROLLED=y by default if not specified.
            if e.returncode != 1:
                logger.warn("[{0}] failed: {1}.\nAgent will continue to publish hostname without NetworkManager restart".format(' '.join(nm_controlled_cmd), e))
        except Exception as e:
            logger.warn("Unexpected error while retrieving value of NM_CONTROLLED in {0}: {1}.\nAgent will continue to publish hostname without NetworkManager restart".format(filepath, e))

        return True

    def get_nic_operational_and_general_states(self, ifname):
        """
        Checks the contents of /sys/class/net/{ifname}/operstate and the results of 'nmcli -g general.state device show {ifname}' to determine the state of the provided interface.
        Raises an exception if the network interface state cannot be determined.
        """
        filepath = "/sys/class/net/{0}/operstate".format(ifname)
        nic_general_state_cmd = ['nmcli', '-g', 'general.state', 'device', 'show', ifname]
        if not os.path.isfile(filepath):
            msg = "Unable to determine primary network interface {0} state, because state file does not exist: {1}".format(ifname, filepath)
            logger.warn(msg)
            raise Exception(msg)

        try:
            nic_oper_state = fileutil.read_file(filepath).rstrip().lower()
            nic_general_state = shellutil.run_command(nic_general_state_cmd, log_error=True).rstrip().lower()
            if nic_oper_state != "up":
                logger.warn("The primary network interface {0} operational state is '{1}'.".format(ifname, nic_oper_state))
            else:
                logger.info("The primary network interface {0} operational state is '{1}'.".format(ifname, nic_oper_state))
            if nic_general_state != "100 (connected)":
                logger.warn("The primary network interface {0} general state is '{1}'.".format(ifname, nic_general_state))
            else:
                logger.info("The primary network interface {0} general state is '{1}'.".format(ifname, nic_general_state))
            return nic_oper_state, nic_general_state
        except Exception as e:
            msg = "Unexpected error while determining the primary network interface state: {0}".format(e)
            logger.warn(msg)
            raise Exception(msg)

    def check_and_recover_nic_state(self, ifname):
        """
        Checks if the provided network interface is in an 'up' state. If the network interface is in a 'down' state,
        attempt to recover the interface by restarting the Network Manager service.

        Raises an exception if an attempt to bring the interface into an 'up' state fails, or if the state
         of the network interface cannot be determined.
        """
        nic_operstate, nic_general_state = self.get_nic_operational_and_general_states(ifname)
        if nic_operstate == "down" or "disconnected" in nic_general_state:
            logger.info("Restarting the Network Manager service to recover network interface {0}".format(ifname))
            self.restart_network_manager()
            # Interface does not come up immediately after NetworkManager restart. Wait 5 seconds before checking
            # network interface state.
            time.sleep(5)
            nic_operstate, nic_general_state = self.get_nic_operational_and_general_states(ifname)
            # It is possible for network interface to be in an unknown or unmanaged state. Log warning if state is not
            # down, disconnected, up, or connected
            if nic_operstate != "up" or nic_general_state != "100 (connected)":
                msg = "Network Manager restart failed to bring network interface {0} into 'up' and 'connected' state".format(ifname)
                logger.warn(msg)
                raise Exception(msg)
            else:
                logger.info("Network Manager restart successfully brought the network interface {0} into 'up' and 'connected' state".format(ifname))
        elif nic_operstate != "up" or nic_general_state != "100 (connected)":
            # We already logged a warning with the network interface state in get_nic_operstate(). Raise an exception
            # for the env thread to send to telemetry.
            raise Exception("The primary network interface {0} operational state is '{1}' and general state is '{2}'.".format(ifname, nic_operstate, nic_general_state))

    def restart_network_manager(self):
        shellutil.run("service NetworkManager restart")

    def publish_hostname(self, hostname, recover_nic=False):
        """
        Restart NetworkManager first before publishing hostname, only if the network interface is not controlled by the
        NetworkManager service (as determined by NM_CONTROLLED=n in the interface configuration). If the NetworkManager
        service is restarted before the agent publishes the hostname, and NM_controlled=y, a race condition may happen
        between the NetworkManager service and the Guest Agent making changes to the network interface configuration
        simultaneously.

        Note: check_and_recover_nic_state(ifname) raises an Exception if an attempt to recover the network interface
        fails, or if the network interface state cannot be determined. Callers should handle this exception by sending
        an event to telemetry.

        TODO: Improve failure reporting and add success reporting to telemetry for hostname changes. Right now we are only reporting failures to telemetry by raising an Exception in publish_hostname for the calling thread to handle by reporting the failure to telemetry.
        """
        ifname = self.get_if_name()
        nm_controlled = self.get_nm_controlled(ifname)
        if not nm_controlled:
            self.restart_network_manager()
        # TODO: Current recover logic is only effective when the NetworkManager manages the network interface. Update the recover logic so it is effective even when NM_CONTROLLED=n
        super(RedhatOSUtil, self).publish_hostname(hostname, recover_nic and nm_controlled)

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


class RedhatOSModernUtil(RedhatOSUtil):
    def __init__(self):  # pylint: disable=W0235
        super(RedhatOSModernUtil, self).__init__()

    def restart_if(self, ifname, retries=3, wait=5):
        """
        Restart an interface by bouncing the link. systemd-networkd observes
        this event, and forces a renew of DHCP.
        """
        retry_limit = retries + 1
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

    def check_and_recover_nic_state(self, ifname):
        # TODO: Implement and test a way to recover the network interface for RedhatOSModernUtil
        pass
