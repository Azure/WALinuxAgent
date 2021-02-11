# -*- encoding: utf-8 -*-
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

import os
import re
import subprocess

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup
from azurelinuxagent.common.cgroupapi import CGroupsApi, SystemdCgroupsApi, SystemdRunError
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation

_AZURE_SLICE = "azure.slice"
_AZURE_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM Agent and Extensions
DefaultDependencies=no
Before=slices.target
"""
_VMEXTENSIONS_SLICE = "azure-vmextensions.slice"
_VMEXTENSIONS_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM Extensions
DefaultDependencies=no
Before=slices.target
[Slice]
CPUAccounting=yes
"""
_AGENT_DROP_IN_FILE_SLICE = "10-Slice.conf"
_AGENT_DROP_IN_FILE_SLICE_CONTENTS = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
Slice=azure.slice
"""
_AGENT_DROP_IN_FILE_CPU_ACCOUNTING = "11-CPUAccounting.conf"
_AGENT_DROP_IN_FILE_CPU_ACCOUNTING_CONTENTS = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
CPUAccounting=yes
"""
_AGENT_DROP_IN_FILE_CPU_QUOTA = "12-CPUQuota.conf"
_AGENT_DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
CPUQuota={0}%
"""
_AGENT_CPU_QUOTA = 5


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command, none of the methods in this class
    raise exceptions (cgroup operations should not block extensions)
    """
    class __Impl(object):
        def __init__(self):
            self._initialized = False
            self._cgroups_supported = False
            self._cgroups_enabled = False
            self._cgroups_api = None
            self._agent_cpu_cgroup_path = None
            self._agent_memory_cgroup_path = None
            self._check_processes_in_agent_cgroup_last_error = None
            self._check_processes_in_agent_cgroup_error_count = 0

        def initialize(self):
            try:
                if self._initialized:
                    return

                # check whether cgroup monitoring is supported on the current distro
                self._cgroups_supported = CGroupsApi.cgroups_supported()
                if not self._cgroups_supported:
                    logger.info("Cgroup monitoring is not supported on {0}", get_distro())
                    return

                # check that systemd is detected correctly
                self._cgroups_api = SystemdCgroupsApi()
                if not systemd.is_systemd():
                    self.__log_cgroup_warning("systemd was not detected on {0}", get_distro())
                    return

                self.__log_cgroup_info("systemd version: {0}", systemd.get_version())

                # This is temporarily disabled while we analyze telemetry. Likely it will be removed.
                # self.__collect_azure_unit_telemetry()
                # self.__collect_agent_unit_files_telemetry()

                if not self.__check_no_legacy_cgroups():
                    return

                agent_unit_name = systemd.get_agent_unit_name()
                agent_slice = systemd.get_unit_property(agent_unit_name, "Slice")
                if agent_slice not in (_AZURE_SLICE, "system.slice"):
                    self.__log_cgroup_warning("The agent is within an unexpected slice: {0}", agent_slice)
                    return

                self.__setup_azure_slice()

                cpu_controller_root, memory_controller_root = self.__get_cgroup_controllers()
                self._agent_cpu_cgroup_path, self._agent_memory_cgroup_path = self.__get_agent_cgroups(agent_slice, cpu_controller_root, memory_controller_root)

                if self._agent_cpu_cgroup_path is not None:
                    self.__log_cgroup_info("Agent CPU cgroup: {0}", self._agent_cpu_cgroup_path)
                    self._cgroups_enabled = True
                    track_throttled_time = self.set_cpu_quota(_AGENT_CPU_QUOTA)
                    CGroupsTelemetry.track_cgroup(CpuCgroup(agent_unit_name, self._agent_cpu_cgroup_path, track_throttled_time=track_throttled_time))

                self.__log_cgroup_info('Cgroups enabled: {0}', self._cgroups_enabled)

            except Exception as exception:
                self.__log_cgroup_warning("Error initializing cgroups: {0}", ustr(exception))
            finally:
                self._initialized = True

        @staticmethod
        def __log_cgroup_info(format_string, *args):
            message = format_string.format(*args)
            logger.info(message)
            add_event(op=WALAEventOperation.CGroupsInfo, message=message)

        @staticmethod
        def __log_cgroup_warning(format_string, *args):
            message = format_string.format(*args)
            logger.info(message)  # log as INFO for now, in the future it should be logged as WARNING
            add_event(op=WALAEventOperation.CGroupsInfo, message=message, is_success=False, log_event=False)

        def __collect_azure_unit_telemetry(self):
            azure_units = []

            try:
                units = shellutil.run_command(['systemctl', 'list-units', 'azure*', '-all'])
                for line in units.split('\n'):
                    match = re.match(r'\s?(azure[^\s]*)\s?', line, re.IGNORECASE)
                    if match is not None:
                        azure_units.append((match.group(1), line))
            except shellutil.CommandError as command_error:
                self.__log_cgroup_warning("Failed to list systemd units: {0}", ustr(command_error))

            for unit_name, unit_description in azure_units:
                unit_slice = "Unknown"
                try:
                    unit_slice = systemd.get_unit_property(unit_name, "Slice")
                except Exception as exception:
                    self.__log_cgroup_warning("Failed to query Slice for {0}: {1}", unit_name, ustr(exception))

                self.__log_cgroup_info("Found an Azure unit under slice {0}: {1}", unit_slice, unit_description)

            if len(azure_units) == 0:
                try:
                    cgroups = shellutil.run_command('systemd-cgls')
                    for line in cgroups.split('\n'):
                        if re.match(r'[^\x00-\xff]+azure\.slice\s*', line, re.UNICODE):
                            logger.info(ustr("Found a cgroup for azure.slice\n{0}").format(cgroups))
                            # Don't add the output of systemd-cgls to the telemetry, since currently it does not support Unicode
                            add_event(op=WALAEventOperation.CGroupsInfo, message="Found a cgroup for azure.slice")
                except shellutil.CommandError as command_error:
                    self.__log_cgroup_warning("Failed to list systemd units: {0}", ustr(command_error))

        def __collect_agent_unit_files_telemetry(self):
            agent_unit_files = []
            agent_service_name = get_osutil().get_service_name()
            try:
                fragment_path = systemd.get_unit_property(agent_service_name, "FragmentPath")
                if fragment_path != "/lib/systemd/system/{0}.service".format(agent_service_name):
                    agent_unit_files.append(fragment_path)
            except Exception as exception:
                self.__log_cgroup_warning("Failed to query the agent's FragmentPath: {0}", ustr(exception))

            try:
                drop_in_paths = systemd.get_unit_property(agent_service_name, "DropInPaths")
                for path in drop_in_paths.split():
                    agent_unit_files.append(path)
            except Exception as exception:
                self.__log_cgroup_warning("Failed to query the agent's DropInPaths: {0}", ustr(exception))

            for unit_file in agent_unit_files:
                try:
                    with open(unit_file, "r") as file_object:
                        self.__log_cgroup_info("Found a custom unit file for the agent: {0}\n{1}", unit_file, file_object.read())
                except Exception as exception:
                    self.__log_cgroup_warning("Can't read {0}: {1}", unit_file, ustr(exception))

        def __check_no_legacy_cgroups(self):
            """
            Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent. When running
            under systemd this could produce invalid resource usage data. Cgroups should not be enabled under this condition.
            """
            legacy_cgroups = self._cgroups_api.cleanup_legacy_cgroups()
            if legacy_cgroups > 0:
                self.__log_cgroup_warning("The daemon's PID was added to a legacy cgroup; will not monitor resource usage.")
                return False
            return True

        def __get_cgroup_controllers(self):
            #
            # check v1 controllers
            #
            cpu_controller_root, memory_controller_root = self._cgroups_api.get_cgroup_mount_points()

            if cpu_controller_root is not None:
                logger.info("The CPU cgroup controller is mounted at {0}", cpu_controller_root)
            else:
                self.__log_cgroup_warning("The CPU cgroup controller is not mounted")

            if memory_controller_root is not None:
                logger.info("The memory cgroup controller is mounted at {0}", memory_controller_root)
            else:
                self.__log_cgroup_warning("The memory cgroup controller is not mounted")

            #
            # check v2 controllers
            #
            cgroup2_mount_point, cgroup2_controllers = self._cgroups_api.get_cgroup2_controllers()
            if cgroup2_mount_point is not None:
                self.__log_cgroup_info("cgroups v2 mounted at {0}.  Controllers: [{1}]", cgroup2_mount_point, cgroup2_controllers)

            return cpu_controller_root, memory_controller_root

        def __setup_azure_slice(self):
            """
            The agent creates "azure.slice" for use by extensions and the agent. The agent runs under "azure.slice" directly and each
            extension runs under its own slice ("Microsoft.CPlat.Extension.slice" in the example below). All the slices for
            extensions are grouped under "vmextensions.slice".

            Example:  -.slice
                      ├─user.slice
                      ├─system.slice
                      └─azure.slice
                        ├─walinuxagent.service
                        │ ├─5759 /usr/bin/python3 -u /usr/sbin/waagent -daemon
                        │ └─5764 python3 -u bin/WALinuxAgent-2.2.53-py2.7.egg -run-exthandlers
                        └─azure-vmextensions.slice
                          └─Microsoft.CPlat.Extension.slice
                              └─5894 /usr/bin/python3 /var/lib/waagent/Microsoft.CPlat.Extension-1.0.0.0/enable.py

            This method ensures that the "azure" and "vmextensions" slices are created. Setup should create those slices
            under /lib/systemd/system; but if they do not exist, __ensure_azure_slices_exist will create them.

            It also creates drop-in files to set the agent's Slice and CPUAccounting if they have not been
            set up in the agent's unit file.

            Lastly, the method also cleans up unit files left over from previous versions of the agent.
            """

            # Older agents used to create this slice, but it was never used. Cleanup the file.
            self._cleanup_unit_file("/etc/systemd/system/system-walinuxagent.extensions.slice")

            unit_file_install_path = systemd.get_unit_file_install_path()
            azure_slice = os.path.join(unit_file_install_path, _AZURE_SLICE)
            vmextensions_slice = os.path.join(unit_file_install_path, _VMEXTENSIONS_SLICE)
            agent_unit_file = systemd.get_agent_unit_file()
            agent_drop_in_path = systemd.get_agent_drop_in_path()
            agent_drop_in_file_slice = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_SLICE)
            agent_drop_in_file_cpu_accounting = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_CPU_ACCOUNTING)

            files_to_create = []

            if not os.path.exists(azure_slice):
                files_to_create.append((azure_slice, _AZURE_SLICE_CONTENTS))

            if not os.path.exists(vmextensions_slice):
                files_to_create.append((vmextensions_slice, _VMEXTENSIONS_SLICE_CONTENTS))

            if fileutil.findre_in_file(agent_unit_file, r"Slice=") is not None:
                self._cleanup_unit_file(agent_drop_in_file_slice)
            else:
                if not os.path.exists(agent_drop_in_file_slice):
                    files_to_create.append((agent_drop_in_file_slice, _AGENT_DROP_IN_FILE_SLICE_CONTENTS))

            if fileutil.findre_in_file(agent_unit_file, r"CPUAccounting=") is not None:
                self._cleanup_unit_file(agent_drop_in_file_cpu_accounting)
            else:
                if not os.path.exists(agent_drop_in_file_cpu_accounting):
                    files_to_create.append((agent_drop_in_file_cpu_accounting, _AGENT_DROP_IN_FILE_CPU_ACCOUNTING_CONTENTS))

            if len(files_to_create) > 0:
                # create the unit files, but if 1 fails remove all and return
                try:
                    for path, contents in files_to_create:
                        self._create_unit_file(path, contents)
                except Exception as exception:
                    self.__log_cgroup_warning("Failed to create unit files for the azure slice: {0}", ustr(exception))
                    for unit_file in files_to_create:
                        self._cleanup_unit_file(unit_file)
                    return

                # reload the systemd configuration; the new slices will be used once the agent's service restarts
                try:
                    logger.info("Executing systemctl daemon-reload...")
                    shellutil.run_command(["systemctl", "daemon-reload"])
                except Exception as exception:
                    self.__log_cgroup_warning("daemon-reload failed (create azure slice): {0}", ustr(exception))

        def _create_unit_file(self, path, contents):
            parent, _ = os.path.split(path)
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o755)
            fileutil.write_file(path, contents)
            self.__log_cgroup_info("Created {0}", path)

        def _cleanup_unit_file(self, path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                    self.__log_cgroup_info("Removed {0}", path)
                except Exception as exception:
                    self.__log_cgroup_warning("Failed to remove {0}: {1}", path, ustr(exception))

        def __get_agent_cgroups(self, agent_slice, cpu_controller_root, memory_controller_root):
            agent_unit_name = systemd.get_agent_unit_name()

            expected_relative_path = os.path.join(agent_slice, agent_unit_name)
            cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_process_cgroup_relative_paths("self")

            if cpu_cgroup_relative_path is None:
                self.__log_cgroup_warning("The agent's process is not within a CPU cgroup")
            else:
                if cpu_cgroup_relative_path == expected_relative_path:
                    self.__log_cgroup_info('CPUAccounting: {0}', systemd.get_unit_property(agent_unit_name, "CPUAccounting"))
                    self.__log_cgroup_info('CPUQuota: {0}', systemd.get_unit_property(agent_unit_name, "CPUQuotaPerSecUSec"))
                else:
                    cpu_cgroup_relative_path = None  # Set the path to None to prevent monitoring
                    self.__log_cgroup_warning(
                        "The Agent is not in the expected CPU cgroup; will not enable monitoring. Cgroup:[{0}] Expected:[{1}]",
                        cpu_cgroup_relative_path,
                        expected_relative_path)

            if memory_cgroup_relative_path is None:
                self.__log_cgroup_warning("The agent's process is not within a memory cgroup")
            else:
                if memory_cgroup_relative_path == expected_relative_path:
                    memory_accounting = systemd.get_unit_property(agent_unit_name, "MemoryAccounting")
                    self.__log_cgroup_info('MemoryAccounting: {0}', memory_accounting)
                else:
                    memory_cgroup_relative_path = None  # Set the path to None to prevent monitoring
                    self.__log_cgroup_warning(
                        "The Agent is not in the expected memory cgroup; will not enable monitoring. CGroup:[{0}] Expected:[{1}]",
                        memory_cgroup_relative_path,
                        expected_relative_path)

            if cpu_controller_root is not None and cpu_cgroup_relative_path is not None:
                agent_cpu_cgroup_path = os.path.join(cpu_controller_root, cpu_cgroup_relative_path)
            else:
                agent_cpu_cgroup_path = None

            if memory_controller_root is not None and memory_cgroup_relative_path is not None:
                agent_memory_cgroup_path = os.path.join(memory_controller_root, memory_cgroup_relative_path)
            else:
                agent_memory_cgroup_path = None

            return agent_cpu_cgroup_path, agent_memory_cgroup_path

        def enabled(self):
            return self._cgroups_enabled

        def enable(self):
            if not self._cgroups_supported:
                raise CGroupsException("Attempted to enable cgroups, but they are not supported on the current platform")
            self._cgroups_enabled = True

        def disable(self):
            self._cgroups_enabled = False
            CGroupsTelemetry.reset()

        def set_cpu_quota(self, quota):
            """
            Sets the agent's CPU quota to the given percentage (100% == 1 CPU) and returns True on success, False otherwise

            This is done using a dropin file in the default dropin directory; any local overrides on the VM will take precedence
            over this setting.
            """
            logger.info("Setting agent's CPUQuota to {0}%", quota)
            return self._set_cpu_quota(quota)

        def reset_cpu_quota(self):
            """
            Removes any CPUQuota on the agent and returns True on success, False otherwise
            """
            logger.info("Resetting agent's CPUQuota")
            return self._set_cpu_quota('')  # setting an empty value resets to the default (infinity)

        def _set_cpu_quota(self, quota):
            try:
                drop_in_file = os.path.join(systemd.get_agent_drop_in_path(), _AGENT_DROP_IN_FILE_CPU_QUOTA)
                contents = _AGENT_DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT.format(quota)
                self._create_unit_file(drop_in_file, contents)
            except Exception as exception:
                logger.info('Failed to set CPUQuota: {0}', ustr(exception))
                return False
            try:
                logger.info("Executing systemctl daemon-reload...")
                shellutil.run_command(["systemctl", "daemon-reload"])
            except Exception as exception:
                self.__log_cgroup_warning("daemon-reload failed (set quota): {0}", ustr(exception))
                return False
            return True

        def check_processes_in_agent_cgroup(self):
            """
            Verifies that the agent's cgroup includes only the current process, its parent, commands started using shellutil and instances of systemd-run
            (those processes correspond, respectively, to the extension handler, the daemon, commands started by the extension handler, and the systemd-run
            commands used to start extensions on their own cgroup).
            Other processes started by the agent (e.g. extensions) and processes not started by the agent (e.g. services installed by extensions) are reported
            as unexpected, since they should belong to their own cgroup.
            """
            if not self.enabled():
                return True

            def log_message(message):
                # Report only a small sample of errors
                if message != self._check_processes_in_agent_cgroup_last_error and self._check_processes_in_agent_cgroup_error_count < 5:
                    self._check_processes_in_agent_cgroup_error_count += 1
                    self._check_processes_in_agent_cgroup_last_error = message
                    logger.info(message)
                    add_event(op=WALAEventOperation.CGroupsDisabled, message=message)

            try:
                daemon = os.getppid()
                extension_handler = os.getpid()
                agent_commands = set()
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands = set()
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())
                agent_cgroup = CGroupsApi.get_processes_in_cgroup(self._agent_cpu_cgroup_path)
                # get the running commands again in case new commands started or completed while we were fetching the processes in the cgroup;
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())

                unexpected = []
                for process in agent_cgroup:
                    # Note that the agent uses systemd-run to start extensions; systemd-run belongs to the agent cgroup, though the extensions don't
                    if process in (daemon, extension_handler) or process in systemd_run_commands:
                        continue
                    # check if the process is a command started by the agent or a descendant of one of those commands
                    current = process
                    while current != 0 and current not in agent_commands:
                        current = self._get_parent(current)
                    if current == 0:
                        unexpected.append(process)
                        if len(unexpected) >= 5:  # collect just a small sample
                            break
                if unexpected:
                    unexpected = self._format_processes(unexpected)
                    unexpected.sort()  # sort the PIDs so that the error message stays more consistent across different calls to this check
                    log_message("The agent's cgroup includes unexpected processes; disabling CPU enforcement. Unexpected: {0}".format(unexpected))
                    self.disable()
                    return False
            except Exception as exception:
                log_message("Failed to check the processes in the agent's cgroup: {0}".format(ustr(exception)))
            return True

        @staticmethod
        def _format_processes(pid_list):
            """
            Formats the given PIDs as a sequence of strings containing the PIDs and their corresponding command line (truncated to 40 chars)
            """
            def get_command_line(pid):
                try:
                    cmdline = '/proc/{0}/cmdline'.format(pid)
                    if os.path.exists(cmdline):
                        with open(cmdline, "r") as cmdline_file:
                            return "[PID: {0}] {1:40.40}".format(pid, cmdline_file.read())
                except Exception:
                    pass
                return "[PID: {0}] UNKNOWN".format(pid)

            return [get_command_line(pid) for pid in pid_list]

        @staticmethod
        def _get_parent(pid):
            """
            Returns the parent of the given process. If the parent cannot be determined returns 0 (which is the PID for the scheduler)
            """
            try:
                stat = '/proc/{0}/stat'.format(pid)
                if os.path.exists(stat):
                    with open(stat, "r") as stat_file:
                        return int(stat_file.read().split()[3])
            except Exception:
                pass
            return 0

        def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, error_code=ExtensionErrorCodes.PluginUnknownFailure):
            """
            Starts a command (install/enable/etc) for an extension and adds the command's PID to the extension's cgroup
            :param extension_name: The extension executing the command
            :param command: The command to invoke
            :param timeout: Number of seconds to wait for command completion
            :param cwd: The working directory for the command
            :param env:  The environment to pass to the command's process
            :param stdout: File object to redirect stdout to
            :param stderr: File object to redirect stderr to
            :param stderr: File object to redirect stderr to
            :param error_code: Extension error code to raise in case of error
            """
            if self.enabled():
                try:
                    return self._cgroups_api.start_extension_command(extension_name, command, timeout, shell=shell, cwd=cwd, env=env, stdout=stdout, stderr=stderr, error_code=error_code)
                except SystemdRunError as exception:
                    event_msg = 'Failed to start extension {0} using systemd-run. Will disable resource enforcement and retry invoking the extension without systemd. ' \
                                'Systemd-run error: {1}'.format(extension_name, ustr(exception))
                    add_event(op=WALAEventOperation.CGroupsDisabled, is_success=False, log_event=False, message=event_msg)
                    logger.info(event_msg)
                    self.disable()
                    # fall-through and re-invoke the extension

            # subprocess-popen-preexec-fn<W1509> Disabled: code is not multi-threaded
            process = subprocess.Popen(command, shell=shell, cwd=cwd, env=env, stdout=stdout, stderr=stderr, preexec_fn=os.setsid)  # pylint: disable=W1509
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout, stderr=stderr, error_code=error_code)

    # unique instance for the singleton
    _instance = None

    @staticmethod
    def get_instance():
        if CGroupConfigurator._instance is None:
            CGroupConfigurator._instance = CGroupConfigurator.__Impl()
        return CGroupConfigurator._instance
