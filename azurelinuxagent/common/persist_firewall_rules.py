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

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.common.utils.networkutil import AddFirewallRules
from azurelinuxagent.common.utils.shellutil import CommandError


class PersistFirewallRulesHandler(object):

    __SERVICE_FILE_CONTENT = """
# This unit file was created by the Azure VM Agent.
# Do not edit.
[Unit]
Description=Setup network rules for WALinuxAgent 
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
Environment="EGG={egg_path}" "DST_IP={wire_ip}" "UID={user_id}" "WAIT={wait}"
ExecStart={py_path} ${{EGG}} --setup-firewall --dst_ip=${{DST_IP}} --uid=${{UID}} ${{WAIT}}
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
Environment="EGG={egg_path}" "DST_IP={wire_ip}" "UID={user_id}" "WAIT={wait}"
"""

    _AGENT_NETWORK_SETUP_NAME_FORMAT = "{0}-network-setup.service"
    _DROP_IN_ENV_FILE_NAME = "10-environment.conf"

    _FIREWALLD_RUNNING_CMD = ["firewall-cmd", "--state"]

    @staticmethod
    def get_service_file_path():
        osutil = get_osutil()
        service_name = PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_NAME_FORMAT.format(osutil.get_service_name())
        return os.path.join(osutil.get_systemd_unit_file_install_path(), service_name)

    def __init__(self, dst_ip, uid):
        """
        This class deals with ensuring that Firewall rules are persisted over system reboots.
        It tries to employ using Firewalld.service if present first as it already has provisions for persistent rules.
        If not, it then creates a new agent-network-setup.service file and copy it over to the osutil.get_systemd_unit_file_install_path() dynamically
        On top of it, on every service restart it ensures that the WireIP is overwritten and the new IP is blocked as well.
        """
        osutil = get_osutil()
        self._network_setup_service_name = self._AGENT_NETWORK_SETUP_NAME_FORMAT.format(osutil.get_service_name())
        self._is_systemd = systemd.is_systemd()
        self._systemd_file_path = osutil.get_systemd_unit_file_install_path()
        self._dst_ip = dst_ip
        self._uid = uid
        self._wait = osutil.get_firewall_will_wait()
        # The custom service will try to call the current agent executable to setup the firewall rules
        self._current_agent_executable_path = os.path.join(os.getcwd(), sys.argv[0])

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
            logger.verbose("{0} command failed: {1}".format(' '.join(firewalld_state), ustr(error)))
        return False

    def setup(self):
        if not systemd.is_systemd():
            logger.warn("Did not detect Systemd, unable to set {0}".format(self._network_setup_service_name))
            return

        if self._is_firewall_service_running():
            logger.info("Firewalld.service present on the VM, setting up permanent rules on the VM")
            # In case of a failure, this would throw. In such a case, we don't need to try to setup our custom service
            # because on system reboot, all iptable rules are reset by firewalld.service so it would be a no-op.
            self._setup_permanent_firewalld_rules()
            return

        logger.info(
            "Firewalld service not running/unavailable, trying to set up {0}".format(self._network_setup_service_name))

        self._setup_network_setup_service()

    def __verify_firewall_rules_enabled(self):
        # Check if firewall-rules have already been enabled
        # This function would also return False if the dest-ip is changed. So no need to check separately for that
        try:
            AddFirewallRules.check_firewalld_rule_applied(self._dst_ip, self._uid)
        except Exception as error:
            logger.verbose(
                "Check if Firewall rules already applied using firewalld.service failed: {0}".format(ustr(error)))
            return False

        return True

    def _setup_permanent_firewalld_rules(self):
        if self.__verify_firewall_rules_enabled():
            logger.info("Firewall rules already set. No change needed.")
            return

        logger.info("Firewall rules not added yet, adding them now using firewalld.service")
        # Add rules if not already set
        AddFirewallRules.add_firewalld_rules(self._dst_ip, self._uid)
        logger.info("Successfully added the firewall commands using firewalld.service")

    def __verify_network_setup_service_enabled(self):
        # Check if the custom service has already been enabled
        cmd = ["systemctl", "is-enabled", self._network_setup_service_name]
        try:
            return shellutil.run_command(cmd).rstrip() == "enabled"
        except CommandError as error:
            msg = "{0} not enabled. Command: {1}, ExitCode: {2}\nStdout: {3}\nStderr: {4}".format(
                self._network_setup_service_name, ' '.join(cmd), error.returncode, error.stdout, error.stderr)
        except Exception as error:
            msg = "Ran into error, {0} not enabled. Error: {1}".format(self._network_setup_service_name, ustr(error))

        logger.verbose(msg)
        return False

    def _setup_network_setup_service(self):
        if self.__verify_network_setup_service_enabled():
            logger.info("Service: {0} already enabled. No change needed.".format(self._network_setup_service_name))
            self.__log_network_setup_service_logs()

        else:
            logger.info("Service: {0} not enabled. Adding it now".format(self._network_setup_service_name))
            # Create unit file with default values
            self.__set_service_unit_file()
            logger.info("Successfully added and enabled the {0}".format(self._network_setup_service_name))

        # Even if service is enabled, we need to overwrite the drop-in file with the current IP in case it changed.
        # This is to handle the case where WireIP can change midway on service restarts.
        # Additionally, incase of auto-update this would also update the location of the new EGG file ensuring that
        # the service is always run from the most latest agent.
        self.__set_drop_in_file()

    def __set_drop_in_file(self):
        drop_in_file = os.path.join(self._systemd_file_path, "{0}.d".format(self._network_setup_service_name),
                                    self._DROP_IN_ENV_FILE_NAME)
        parent, _ = os.path.split(drop_in_file)
        try:
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o755)
            fileutil.write_file(drop_in_file,
                                self.__OVERRIDE_CONTENT.format(egg_path=self._current_agent_executable_path,
                                                               wire_ip=self._dst_ip,
                                                               user_id=self._uid,
                                                               wait=self._wait))
            logger.info("Drop-in file {0} successfully updated".format(drop_in_file))
        except Exception:
            self.__remove_file_without_raising(drop_in_file)
            raise

    def __set_service_unit_file(self):
        service_unit_file = self.get_service_file_path()
        try:
            fileutil.write_file(service_unit_file,
                                self.__SERVICE_FILE_CONTENT.format(egg_path=self._current_agent_executable_path,
                                                                   wire_ip=self._dst_ip,
                                                                   user_id=self._uid,
                                                                   wait=self._wait,
                                                                   py_path=sys.executable))
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

    def __verify_network_setup_service_failed(self):
        # Check if the agent-network-setup.service failed in its last run
        # Note:
        # The `systemctl is-failed <service>` command would return "failed" and ExitCode: 0 if the service was actually
        # in a failed state.
        # For the rest of the cases (eg: active, in-active, dead, etc) it would return the state and a non-0 ExitCode.
        cmd = ["systemctl", "is-failed", self._network_setup_service_name]
        try:
            return shellutil.run_command(cmd).rstrip() == "failed"
        except CommandError as error:
            msg = "{0} not in a failed state. Command: {1}, ExitCode: {2}\nStdout: {3}\nStderr: {4}".format(
                self._network_setup_service_name, ' '.join(cmd), error.returncode, error.stdout, error.stderr)
        except Exception as error:
            msg = "Ran into error, {0} not failed. Error: {1}".format(self._network_setup_service_name, ustr(error))

        logger.verbose(msg)
        return False

    def __log_network_setup_service_logs(self):
        # Get logs from journalctl - https://www.freedesktop.org/software/systemd/man/journalctl.html
        cmd = ["journalctl", "-u", self._network_setup_service_name, "-b"]
        service_failed = self.__verify_network_setup_service_failed()
        try:
            stdout = shellutil.run_command(cmd)
            msg = "Logs from the {0} since system boot:\n {1}".format(self._network_setup_service_name, stdout)
            logger.info(msg)
        except CommandError as error:
            msg = "Unable to fetch service logs, Command: {0} failed with ExitCode: {1}\nStdout: {2}\nStderr: {3}".format(
                ' '.join(cmd), error.returncode, error.stdout, error.stderr)
            logger.warn(msg)
        except Exception as error:
            msg = "Ran into unexpected error when getting logs for {0} service. Error: {1}".format(
                self._network_setup_service_name, ustr(error))
            logger.warn(msg)

        # Log service status and logs if we can fetch them from journalctl and send it to Kusto,
        # else just log the error of the failure of fetching logs
        add_event(
            op=WALAEventOperation.PersistFirewallRules,
            is_success=(not service_failed),
            message=msg,
            log_event=False)
