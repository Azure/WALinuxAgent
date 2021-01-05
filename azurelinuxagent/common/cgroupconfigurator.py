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
import subprocess

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupapi import CGroupsApi, SystemdCgroupsApi
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation


class UnexpectedProcessesInCGroupException(CGroupsException):
    """
    Raised by CGroupConfigurator.check_processes_in_agent_cgroup() when the agent's cgroup includes processes
    that should not belong to it.
    The 'unexpected' property is a list of the processes (strings) that should not belong to the agent's cgroup
    """
    def __init__(self, unexpected):
        super(UnexpectedProcessesInCGroupException, self).__init__("Unexpected processes in agent's cgroup")
        self.unexpected = unexpected


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command and check_processes_in_agent_cgroup, none of the methods in this class
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
            self._get_processes_in_agent_cgroup_last_error = None
            self._get_processes_in_agent_cgroup_error_count = 0

        def initialize(self):
            try:
                if self._initialized:
                    return

                #
                # check whether cgroup monitoring is supported on the current distro
                #
                self._cgroups_supported = CGroupsApi.cgroups_supported()
                if not self._cgroups_supported:
                    logger.info("Cgroup monitoring is not supported on {0}", get_distro())
                    return

                #
                # check systemd
                #
                self._cgroups_api = SystemdCgroupsApi()

                if not self._cgroups_api.is_systemd():
                    message = "systemd was not detected on {0}".format(get_distro())
                    logger.warn(message)
                    add_event(op=WALAEventOperation.CGroupsInitialize, is_success=False, message=message, log_event=False)
                    return

                def log_cgroup_info(format_string, *args):
                    message = format_string.format(*args)
                    logger.info(message)
                    add_event(op=WALAEventOperation.CGroupsInfo, message=message)

                log_cgroup_info("systemd version: {0}", self._cgroups_api.get_systemd_version())

                #
                # Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent.  When running
                # under systemd this could produce invalid resource usage data. Do not enable cgroups under this condition.
                #
                legacy_cgroups = self._cgroups_api.cleanup_legacy_cgroups()

                if legacy_cgroups > 0:
                    log_cgroup_info("The daemon's PID was added to a legacy cgroup; will not monitor resource usage.")
                    return

                #
                # check v1 controllers
                #
                cpu_controller_root, memory_controller_root = self._cgroups_api.get_cgroup_mount_points()

                if cpu_controller_root is not None:
                    logger.info("The CPU cgroup controller is mounted at {0}", cpu_controller_root)
                else:
                    log_cgroup_info("The CPU cgroup controller is not mounted")

                if memory_controller_root is not None:
                    logger.info("The memory cgroup controller is mounted at {0}", memory_controller_root)
                else:
                    log_cgroup_info("The memory cgroup controller is not mounted")

                #
                # check v2 controllers
                #
                cgroup2_mount_point, cgroup2_controllers = self._cgroups_api.get_cgroup2_controllers()
                if cgroup2_mount_point is not None:
                    log_cgroup_info("cgroups v2 mounted at {0}.  Controllers: [{1}]", cgroup2_mount_point, cgroup2_controllers)

                #
                # check the cgroups for the agent
                #
                agent_unit_name = self._cgroups_api.get_agent_unit_name()
                cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_process_cgroup_relative_paths("self")
                expected_relative_path = os.path.join('system.slice', agent_unit_name)
                if cpu_cgroup_relative_path is None:
                    log_cgroup_info("The agent's process is not within a CPU cgroup")
                else:
                    if cpu_cgroup_relative_path != expected_relative_path:
                        log_cgroup_info("The Agent is not in the expected cgroup; will not enable cgroup monitoring. CPU relative path:[{0}] Expected:[{1}]", cpu_cgroup_relative_path, expected_relative_path)
                        return
                    cpu_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "CPUAccounting")
                    log_cgroup_info('CPUAccounting: {0}', cpu_accounting)

                if memory_cgroup_relative_path is None:
                    log_cgroup_info("The agent's process is not within a memory cgroup")
                else:
                    if memory_cgroup_relative_path != expected_relative_path:
                        log_cgroup_info("The Agent is not in the expected cgroup; will not enable cgroup monitoring. Memory relative path:[{0}] Expected:[{1}]", memory_cgroup_relative_path, expected_relative_path)
                        return
                    memory_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "MemoryAccounting")
                    log_cgroup_info('MemoryAccounting: {0}', memory_accounting)

                #
                # All good, enable cgroups and start monitoring the agent
                #
                if cpu_controller_root is None or cpu_cgroup_relative_path is None:
                    logger.info("Will not track CPU for the agent's cgroup")
                else:
                    self._agent_cpu_cgroup_path = os.path.join(cpu_controller_root, cpu_cgroup_relative_path)
                    log_cgroup_info("Agent CPU cgroup: {0}", self._agent_cpu_cgroup_path)
                    CGroupsTelemetry.track_cgroup(CpuCgroup(agent_unit_name, self._agent_cpu_cgroup_path))

                if memory_controller_root is None or memory_cgroup_relative_path is None:
                    logger.info("Will not track memory for the agent's cgroup")
                else:
                    self._agent_memory_cgroup_path = os.path.join(memory_controller_root, memory_cgroup_relative_path)
                    log_cgroup_info("Agent Memory cgroup: {0}", self._agent_memory_cgroup_path)
                    CGroupsTelemetry.track_cgroup(MemoryCgroup(agent_unit_name, self._agent_memory_cgroup_path))

                if self._agent_cpu_cgroup_path is not None or self._agent_memory_cgroup_path is not None:
                    self._cgroups_enabled = True

                log_cgroup_info('Cgroups enabled: {0}', self._cgroups_enabled)

            except Exception as exception:
                message = "Error initializing cgroups: {0}".format(ustr(exception))
                logger.warn(message)
                add_event(op=WALAEventOperation.CGroupsInitialize, is_success=False, message=message, log_event=False)
            finally:
                self._initialized = True

        def enabled(self):
            return self._cgroups_enabled

        def resource_limits_enforced(self):
            return False

        def enable(self):
            if not self._cgroups_supported:
                raise CGroupsException("Attempted to enable cgroups, but they are not supported on the current platform")

            self._cgroups_enabled = True

        def disable(self):
            self._cgroups_enabled = False
            CGroupsTelemetry.reset()

        def create_slices(self):
            if not self.enabled():
                return

            # Create root slices for agent and agent and extensions for systemd-managed distros.
            # The hierarchy is as follows:
            # ├─user.slice
            # ...
            # ├─system.slice
            # ...
            # └─azure.slice
            #   └─azure-vmextensions.slice

            # Both methods will log to local log and emit telemetry.
            # The slices will be created if they don't previously exist.

            if not os.path.exists(SystemdCgroupsApi.get_azure_slice()):
                self.create_azure_slice()

            if not os.path.exists(SystemdCgroupsApi.get_extensions_slice()):
                self.create_extensions_slice()

        def create_azure_slice(self):
            """"
            Creates the slice for the VM Agent and extensions.
            """
            if not self.enabled():
                return

            try:
                self._cgroups_api.create_azure_slice()
            except Exception as exception:
                error_message = "Failed to create the azure slice. Error: {0}".format(ustr(exception))
                logger.warn(error_message)
                add_event(op=WALAEventOperation.CGroupsInitialize, message=error_message)

        def create_extensions_slice(self):
            """
            Creates the slice that includes the cgroups for all extensions
            """
            if not self.enabled():
                return

            try:
                self._cgroups_api.create_extensions_slice()
            except Exception as exception:
                error_message = "Failed to create slice for VM extensions. Error: {0}".format(ustr(exception))
                logger.warn(error_message)
                add_event(op=WALAEventOperation.CGroupsInitialize, message=error_message)

        def check_processes_in_agent_cgroup(self):
            """
            Verifies that the agent's cgroup includes only the current process, its parent, commands started using shellutil and instances of systemd-run
            (those processes correspond, respectively, to the extension handler, the daemon, commands started by the extension handler, and the systemd-run
            commands used to start extensions on their own cgroup).
            Other processes started by the agent (e.g. extensions) and processes not started by the agent (e.g. services installed by extensions) are reported
            as unexpected, since they should belong to their own cgroup.
            The function raises an UnexpectedProcessesInCGroupException if the check fails.
            """
            if not self.enabled():
                return

            daemon = os.getppid()
            extension_handler = os.getpid()
            agent_commands = set()
            agent_commands.update(shellutil.get_running_commands())
            systemd_run_commands = set()
            systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())
            agent_cgroup = CGroupsApi.get_processes_in_cgroup(self._agent_cpu_cgroup_path)
            # get the running commands again in case new commands were started while we were fetching the processes in the cgroup;
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
                raise UnexpectedProcessesInCGroupException(unexpected=self._format_processes(unexpected))

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
            if not self.enabled():
                # subprocess-popen-preexec-fn<W1509> Disabled: code is not multi-threaded
                process = subprocess.Popen(command,  # pylint: disable=W1509
                                           shell=shell,
                                           cwd=cwd,
                                           env=env,
                                           stdout=stdout,
                                           stderr=stderr,
                                           preexec_fn=os.setsid)

                process_output = handle_process_completion(process=process,
                                                           command=command,
                                                           timeout=timeout,
                                                           stdout=stdout,
                                                           stderr=stderr,
                                                           error_code=error_code)
            else:
                process_output = self._cgroups_api.start_extension_command(extension_name,
                                                                          command, 
                                                                          timeout, 
                                                                          shell=shell, 
                                                                          cwd=cwd, 
                                                                          env=env, 
                                                                          stdout=stdout, 
                                                                          stderr=stderr, 
                                                                          error_code=error_code) 

            return process_output

    # unique instance for the singleton
    _instance = None

    @staticmethod
    def get_instance():
        if CGroupConfigurator._instance is None:
            CGroupConfigurator._instance = CGroupConfigurator.__Impl()
        return CGroupConfigurator._instance
