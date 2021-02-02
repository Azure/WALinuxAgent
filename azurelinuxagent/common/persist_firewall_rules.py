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
import sys

import shutil

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroupapi import CGroupsApi
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.common.utils.networkutil import AddFirewallRules
from azurelinuxagent.common.utils.shellutil import CommandError


class PersistFirewallRulesHandler(object):

    __SERVICE_FILE_CONTENT = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Unit]
Description=Setup network rules for WALinuxAgent 
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no
ConditionPathExists={0}

[Service]
Type=oneshot
Environment="DST_IP={1}" "UID={2}" "WAIT={3}"
ExecStart={4} {0} --dst_ip=${{DST_IP}} --uid=${{UID}} ${{WAIT}}
RemainAfterExit=false

[Install]
WantedBy=network.target
"""

    __OVERRIDE_CONTENT = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
# The first line clears the old data, and the 2nd line overwrites it.
Environment=
Environment="DST_IP={0}" "UID={1}" "WAIT={2}"
"""

    _AGENT_NETWORK_SETUP_BIN_FILE = "waagent_network_setup.py"
    _AGENT_NETWORK_SETUP_NAME_FORMAT = "{0}-network-setup.service"
    _DROP_IN_ENV_FILE_NAME = "10-environment.conf"

    _FIREWALLD_RUNNING_CMD = ["firewall-cmd", "--state"]

    def __init__(self, dst_ip, uid):
        """
        This class deals with ensuring that Firewall rules are persisted over system reboots.
        It tries to employ using Firewalld.service if present first as it already has provisions for persistent rules.
        If not, it then creates a new agent-network-setup.service file and copy it over to the osutil.get_systemd_unit_file_install_path() dynamically
        On top of it, on every service restart it ensures that the WireIP is overwritten and the new IP is blocked as well.
        """
        osutil = get_osutil()
        self._network_setup_service_name = self._AGENT_NETWORK_SETUP_NAME_FORMAT.format(osutil.get_service_name())
        self._is_systemd = CGroupsApi.is_systemd()
        self._systemd_file_path = osutil.get_systemd_unit_file_install_path()
        self._agent_network_setup_bin_file = os.path.join(osutil.get_agent_bin_path(), self._AGENT_NETWORK_SETUP_BIN_FILE)
        self._dst_ip = dst_ip
        self._uid = uid
        self._wait = osutil.get_firewall_will_wait()

    @staticmethod
    def _is_firewall_service_running():
        # Check if firewall-cmd can connect to the daemon
        # https://docs.fedoraproject.org/en-US/Fedora/19/html/Security_Guide/sec-Check_if_firewalld_is_running.html
        # Eg:    firewall-cmd --state
        #           >   running
        firewalld_state = PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD
        try:
            return shellutil.run_command(firewalld_state).rstrip() == "running"
        except Exception as error:
            logger.info("{0} command returned error/not running: {1}".format(' '.join(firewalld_state), ustr(error)))
        return False

    def setup(self):
        if self._is_firewall_service_running():
            logger.info("Firewalld.service present on the VM, setting up permanent rules on the VM")
            # Incase of a failure, this would throw. In such a case, we don't need to try to setup our custom service
            # because on system reboot, all iptable rules are reset by firewalld.service so it would be a no-op.
            self._setup_permanent_firewalld_rules()
            return

        logger.info(
            "Firewalld service not running/unavailable, trying to set up {0}".format(self._network_setup_service_name))

        if not CGroupsApi.is_systemd():
            raise Exception("Systemd not enabled, unable to set {0}".format(self._network_setup_service_name))

        self._setup_network_setup_service()

    def __verify_firewall_rules_enabled(self):
        # Check if firewall-rules have already been enabled
        # This function would also return False if the dest-ip is changed. So no need to check separately for that
        try:
            AddFirewallRules.check_firewalld_rule_applied(self._wait, self._dst_ip, self._uid)
        except Exception as error:
            logger.warn("Firewall Rules not applied: {0}\n. Setting them now".format(ustr(error)))
            return False

        return True

    def _setup_permanent_firewalld_rules(self):
        if self.__verify_firewall_rules_enabled():
            logger.info("Firewall rules already set. No change needed.")
            return

        # Add rules if not already set
        AddFirewallRules.add_firewalld_rules(self._wait, self._dst_ip, self._uid)
        logger.info("Successfully set the firewall commands using firewalld.service")

    def __verify_network_setup_service_enabled(self):
        # Check if the custom service has already been enabled
        cmd = ["systemctl", "is-enabled", self._network_setup_service_name]
        try:
            return shellutil.run_command(cmd).rstrip() == "enabled"
        except Exception as error:
            msg = "Ran into error, {0} not enabled. Error: {1}".format(self._network_setup_service_name, ustr(error))
            if isinstance(error, CommandError):
                msg = "{0}. Command: {1}, ExitCode: {2}\nStdout: {3}\nStderr: {4}".format(msg, ' '.join(cmd),
                                                                                          error.returncode,
                                                                                          error.stdout,
                                                                                          error.stderr)
            logger.info(msg)
            return False

    def _setup_network_setup_service(self):
        if self.__verify_network_setup_service_enabled():
            logger.info("Service: {0} already enabled. No change needed.".format(self._network_setup_service_name))
        else:
            # Ensure waagent_network_setup.py is available in the desired spot
            self.__set_network_setup_bin_file()
            # Create unit file with default values
            self.__set_service_unit_file()

        # Even if service is enabled, we need to overwrite the drop-in file with the current IP incase it changed.
        # This is to handle the case where WireIP can change midway on service restarts.
        self.__set_drop_in_file()

    def __set_network_setup_bin_file(self):
        if os.path.exists(self._agent_network_setup_bin_file):
            logger.verbose("{0} file exists in the expected place".format(self._agent_network_setup_bin_file))
            return

        logger.warn("Network file: {0} not available in the expected path. Copying it over".format(
            self._agent_network_setup_bin_file))
        try:
            parent, _ = os.path.split(os.path.abspath(__file__))
            shutil.copyfile(os.path.join(parent, fileutil.base_name(self._agent_network_setup_bin_file)),
                            self._agent_network_setup_bin_file)
            fileutil.chmod(self._agent_network_setup_bin_file, 0o744)
        except Exception:
            self.__remove_file_without_raising(self._agent_network_setup_bin_file)
            raise

    def __set_drop_in_file(self):
        drop_in_file = os.path.join(self._systemd_file_path, "{0}.d".format(self._network_setup_service_name),
                                    self._DROP_IN_ENV_FILE_NAME)
        parent, _ = os.path.split(drop_in_file)
        try:
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o644)
            fileutil.write_file(drop_in_file, self.__OVERRIDE_CONTENT.format(self._dst_ip, self._uid, self._wait))
        except Exception:
            self.__remove_file_without_raising(drop_in_file)
            raise

    def __set_service_unit_file(self):
        service_unit_file = os.path.join(self._systemd_file_path, self._network_setup_service_name)
        try:
            fileutil.write_file(service_unit_file,
                                self.__SERVICE_FILE_CONTENT.format(self._agent_network_setup_bin_file, self._dst_ip,
                                                                   self._uid, self._wait, sys.executable))
            fileutil.chmod(service_unit_file, 0o644)

            # Finally enable the service. This is needed to ensure the service is started on system boot
            cmd = ["systemctl", "enable", self._network_setup_service_name]
            try:
                shellutil.run_command(cmd)
            except CommandError as error:
                msg = "Unable to enable service: {0}; deleting service file: {1}. Command: {2}, Exit-code: {3}.\nstdout: {4}\nstderr: {5}".format(
                    self._network_setup_service_name, service_unit_file, ' '.join(cmd), error.returncode, error.stdout,
                    error.stderr)
                raise Exception(msg)

        except Exception:
            self.__remove_file_without_raising(service_unit_file)
            raise

    @staticmethod
    def __remove_file_without_raising(file_path):
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as error:
                logger.warn("Unable to delete file: {0}; Error: {1}".format(file_path, ustr(error)))
