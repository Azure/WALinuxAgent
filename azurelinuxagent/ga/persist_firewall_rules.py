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

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.ga.firewall_manager import FirewallCmd, FirewallStateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.utils import shellutil, fileutil, textutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import get_distro


class PersistFirewallRulesHandler(object):

    __SERVICE_FILE_CONTENT = """
# This unit file (Version={version}) was created by the Azure VM Agent.
# Do not edit.
[Unit]
Description=Setup network rules for WALinuxAgent
After=local-fs.target 
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no
ConditionPathExists={binary_path}

[Service]
Type=oneshot
ExecStart={py_path} {binary_path}
RemainAfterExit=yes

[Install]
WantedBy=network.target
"""

    __BINARY_CONTENTS = """
# This python file was created by the Azure VM Agent. Please do not edit.

import os 


if __name__ == '__main__':
    if os.path.exists("{egg_path}"):
        os.system("{py_path} {egg_path} --setup-firewall={wire_ip}")
    else:
        print("{egg_path} file not found, skipping execution of firewall execution setup for this boot")
"""

    _AGENT_NETWORK_SETUP_NAME_FORMAT = "{0}-network-setup.service"
    BINARY_FILE_NAME = "waagent-network-setup.py"

    # The current version of the unit file; Update it whenever the unit file is modified to ensure Agent can dynamically
    # modify the unit file on VM too
    _UNIT_VERSION = "1.4"

    _DISTRO = get_distro()[0]

    @staticmethod
    def get_service_file_path():
        osutil = get_osutil()
        service_name = PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_NAME_FORMAT.format(osutil.get_service_name())
        return os.path.join(osutil.get_network_setup_service_install_path(), service_name)

    def __init__(self, dst_ip):
        """
        This class deals with ensuring that Firewall rules are persisted over system reboots.
        It tries to employ using Firewalld.service if present first as it already has provisions for persistent rules.
        If not, it then creates a new agent-network-setup.service file and copy it over to the osutil.get_network_setup_service_install_path() dynamically
        On top of it, on every service restart it ensures that the WireIP is overwritten and the new IP is blocked as well.
        """
        osutil = get_osutil()
        self._network_setup_service_name = self._AGENT_NETWORK_SETUP_NAME_FORMAT.format(osutil.get_service_name())
        self._is_systemd = systemd.is_systemd()
        self._systemd_file_path = osutil.get_network_setup_service_install_path()
        self._dst_ip = dst_ip
        # The custom service will try to call the current agent executable to setup the firewall rules
        self._current_agent_executable_path = os.path.join(os.getcwd(), sys.argv[0])

    @staticmethod
    def _is_firewall_service_running():
        # Check if firewall-cmd can connect to the daemon
        # https://docs.fedoraproject.org/en-US/Fedora/19/html/Security_Guide/sec-Check_if_firewalld_is_running.html
        # Eg:    firewall-cmd --state
        #           >   running
        try:
            status = shellutil.run_command(["firewall-cmd", "--state"]).rstrip()
            if status == "running":
                logger.info("The firewalld service is running")
                return True
            else:
                logger.info("The firewalld service is present, but not running: {0}".format(status))
                return False
        except Exception as error:
            # Instance of 'Exception' has no 'errno' member (no-member)
            # OK to disable, errno is a member of IOError
            if isinstance(error, IOError) and error.errno == 2:  # pylint: disable=no-member
                logger.info("The firewalld service is not present on the system")
                return False
            logger.info("The firewalld service is present, but not running: {0}".format(ustr(error)))
            return False

    def setup(self):

        if not self._is_firewall_service_running():
            logger.info("Firewalld service not running/unavailable, trying to set up {0}".format(self.get_service_file_path()))
            if systemd.is_systemd():
                self._setup_network_setup_service()
            else:
                event.info(WALAEventOperation.PersistFirewallRules, "Did not detect systemd, will not set {0}", self._network_setup_service_name)
            return

        event.info(WALAEventOperation.PersistFirewallRules,"Firewalld.service is running, setting up permanent rules on the VM")
        # In case of a failure, this would throw. In such a case, we don't need to try to setup our custom service
        # because on system reboot, all iptables rules are reset by firewalld.service, so it would be a no-op.
        # setup permanent firewalld rules
        firewall_manager = FirewallCmd(self._dst_ip)
        event.info(WALAEventOperation.Firewall, "Using firewall-cmd [version {0}] to manage the persistent firewall rules", firewall_manager.version)

        try:
            firewall_manager.remove_legacy_rule()
        except Exception as error:
            event.error(WALAEventOperation.Firewall, "Unable to remove legacy firewall rule. Error: {0}", ustr(error))

        try:
            if firewall_manager.check():
                event.info(WALAEventOperation.PersistFirewallRules, "The permanent firewall rules for Azure Fabric are already setup:\n{0}", firewall_manager.get_state())
            else:
                firewall_manager.setup()
                event.info(WALAEventOperation.PersistFirewallRules, "Created permanent firewall rules for Azure Fabric:\n{0}", firewall_manager.get_state())
        except FirewallStateError as e:
            event.warn(
                WALAEventOperation.PersistFirewallRules,
                "The permanent firewall rules for Azure Fabric are not setup correctly ({0}), will reset them. Current state:\n{1}", ustr(e), firewall_manager.get_state())
            firewall_manager.remove()
            firewall_manager.setup()
            event.info(WALAEventOperation.PersistFirewallRules, "Reset permanent firewall rules for Azure Fabric:\n{0}", firewall_manager.get_state())

        # Remove custom service if exists to avoid problems with firewalld
        try:
            for file in [self.get_service_file_path(), os.path.join(conf.get_lib_dir(), self.BINARY_FILE_NAME)]:
                if os.path.isfile(file):
                    logger.info("Removing custom firewall service: {0}".format(file))
                    os.remove(file)
        except Exception as error:
            logger.info("Unable to delete existing service {0}: {1}".format(self._network_setup_service_name, ustr(error)))

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
        # Even if service is enabled, we need to overwrite the binary file with the current IP in case it changed.
        # This is to handle the case where WireIP can change midway on service restarts.
        # Additionally, incase of auto-update this would also update the location of the new EGG file ensuring that
        # the service is always run from the most latest agent.

        # If RHEL and in image mode, we need to clean up the service file in old path
        if self._DISTRO == 'rhel' and os.path.exists('/run/ostree-booted'):
            old_service_file_path = os.path.join('/usr/lib/systemd/system/', self._network_setup_service_name)
            if os.path.exists(old_service_file_path):
                logger.info("Cleaning up old service file in image mode: {0}".format(old_service_file_path))
                try:
                    fileutil.rm_files(old_service_file_path)
                except Exception as error:
                    logger.warn("Unable to delete old service in image mode {0}: {1}".format(self._network_setup_service_name, ustr(error)))

        self.__setup_binary_file()

        network_service_enabled = self.__verify_network_setup_service_enabled()
        if network_service_enabled and not self.__should_update_unit_file():
            event.info(WALAEventOperation.PersistFirewallRules, "Service: {0} already enabled. No change needed.", self._network_setup_service_name)
            self.__log_network_setup_service_logs()

        else:
            if not network_service_enabled:
                logger.info("Service: {0} not enabled. Adding it now".format(self._network_setup_service_name))
            else:
                logger.info(
                    "Unit file {0} version modified to {1}, setting it up again".format(self.get_service_file_path(), self._UNIT_VERSION))

            # Create unit file with default values
            self.__set_service_unit_file()
            # After modifying the service, systemctl may issue a warning when checking the service, and daemon-reload should not be used to clear the warning, since it can affect other services
            event.info(WALAEventOperation.PersistFirewallRules, "Successfully added and enabled the {0}", self._network_setup_service_name)

    def __setup_binary_file(self):
        binary_file_path = os.path.join(conf.get_lib_dir(), self.BINARY_FILE_NAME)
        try:
            fileutil.write_file(binary_file_path,
                                self.__BINARY_CONTENTS.format(egg_path=self._current_agent_executable_path,
                                                              wire_ip=self._dst_ip,
                                                              py_path=sys.executable))
            logger.info("Successfully updated the Binary file {0} for firewall setup".format(binary_file_path))
        except Exception:
            logger.warn(
                "Unable to setup binary file, removing the service unit file {0} to ensure its not run on system reboot".format(
                    self.get_service_file_path()))
            self.__remove_file_without_raising(binary_file_path)
            self.__remove_file_without_raising(self.get_service_file_path())
            raise

    def __set_service_unit_file(self):
        service_unit_file = self.get_service_file_path()
        binary_path = os.path.join(conf.get_lib_dir(), self.BINARY_FILE_NAME)
        try:
            fileutil.write_file(service_unit_file,
                                self.__SERVICE_FILE_CONTENT.format(binary_path=binary_path,
                                                                   py_path=sys.executable,
                                                                   version=self._UNIT_VERSION))
            fileutil.chmod(service_unit_file, 0o644)

            # Finally enable the service. This is needed to ensure the service is started on system boot
            cmd = ["systemctl", "enable", self._network_setup_service_name]
            try:
                shellutil.run_command(cmd)
            except CommandError as error:
                msg = ustr(
                    "Unable to enable service: {0}; deleting service file: {1}. Command: {2}, Exit-code: {3}.\nstdout: {4}\nstderr: {5}").format(
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
        cmd = ["journalctl", "-u", self._network_setup_service_name, "-b", "--utc"]
        service_failed = self.__verify_network_setup_service_failed()
        try:
            stdout = shellutil.run_command(cmd)
            msg = ustr("Logs from the {0} since system boot:\n{1}").format(self._network_setup_service_name, stdout)
            logger.info(msg)
        except CommandError as error:
            msg = "Unable to fetch service logs, Command: {0} failed with ExitCode: {1}\nStdout: {2}\nStderr: {3}".format(
                ' '.join(cmd), error.returncode, error.stdout, error.stderr)
            logger.warn(msg)
        except Exception as e:
            msg = "Ran into unexpected error when getting logs for {0} service. Error: {1}".format(
                self._network_setup_service_name, textutil.format_exception(e))
            logger.warn(msg)

        # Log service status and logs if we can fetch them from journalctl and send it to Kusto,
        # else just log the error of the failure of fetching logs
        add_event(
            op=WALAEventOperation.FirewallBootSetup,
            is_success=(not service_failed),
            message=msg,
            log_event=False)

    def __get_unit_file_version(self):
        if not os.path.exists(self.get_service_file_path()):
            raise OSError("{0} not found".format(self.get_service_file_path()))

        match = fileutil.findre_in_file(self.get_service_file_path(),
                                        line_re="This unit file \\(Version=([\\d.]+)\\) was created by the Azure VM Agent.")
        if match is None:
            raise ValueError("Version tag not found in the unit file")

        return match.group(1).strip()

    def __get_unit_exec_start(self):
        if not os.path.exists(self.get_service_file_path()):
            raise OSError("{0} not found".format(self.get_service_file_path()))

        match = fileutil.findre_in_file(self.get_service_file_path(),
                                        line_re="ExecStart=(.*)")
        if match is None:
            raise ValueError("ExecStart tag not found in the unit file")

        return match.group(1).strip()

    def __should_update_unit_file(self):
        """
        Check if the unit file version changed from the expected version or if the exec-start changed from the expected exec-start
        :return: True if unit file need update else False
        """

        try:
            unit_file_version = self.__get_unit_file_version()
            unit_exec_start = self.__get_unit_exec_start()
        except Exception as error:
            logger.info("Unable to read content of unit file: {0}, overwriting unit file".format(ustr(error)))
            # Since we can't determine the version or exec start, marking the file as modified to overwrite the unit file
            return True

        if unit_file_version != self._UNIT_VERSION:
            logger.info(
                "Unit file version: {0} does not match with expected version: {1}, overwriting unit file".format(
                    unit_file_version, self._UNIT_VERSION))
            return True
        binary_path = os.path.join(conf.get_lib_dir(), self.BINARY_FILE_NAME)
        expected_exec_start = "{0} {1}".format(sys.executable, binary_path)
        if unit_exec_start != expected_exec_start:
            logger.info(
                "Unit file exec-start: {0} does not match with expected exec-start: {1}, overwriting unit file".format(
                    unit_exec_start, expected_exec_start))
            return True

        logger.info(
            "Unit file matches with expected version: {0} and exec start: {1}, not overwriting unit file".format(unit_file_version, unit_exec_start))
        return False

