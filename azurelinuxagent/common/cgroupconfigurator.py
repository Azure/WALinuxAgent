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
from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupapi import CGroupsApi, SystemdCgroupsApi
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command, none of the methods in this class raise exceptions (cgroup operations should not block extensions)
    """
    # too-many-instance-attributes<R0902> Disabled: class complexity is OK
    # invalid-name<C0103> Disabled: class is private, so name starts with __
    class __Impl(object):  # pylint: disable=R0902,C0103
        def __init__(self):
            self._initialized = False
            self._cgroups_supported = False
            self._cgroups_enabled = False
            self._cgroups_api = None
            self._agent_cpu_cgroup_path = None
            self._agent_memory_cgroup_path = None
            self._get_processes_in_agent_cgroup_last_error = None
            self._get_processes_in_agent_cgroup_error_count = 0

        # too-many-branches<R0912> Disabled: branches are sequential, not nested
        def initialize(self):  # pylint: disable=R0912
            # pylint: disable=too-many-locals
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
                self._cgroups_api = CGroupsApi.create()

                if not isinstance(self._cgroups_api, SystemdCgroupsApi):
                    message = "systemd was not detected on {0}".format(get_distro())
                    logger.warn(message)
                    add_event(op=WALAEventOperation.CGroupsInitialize, is_success=False, message=message, log_event=False)
                    return

                def log_cgroup_info(format_string, *args):
                    message = format_string.format(*args)
                    logger.info(message)
                    add_event(op=WALAEventOperation.CGroupsInfo, message=message)

                log_cgroup_info("systemd version: {0}", self._cgroups_api.get_systemd_version())  # pylint: disable=E1101

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
                cpu_controller_root, memory_controller_root = self._cgroups_api.get_cgroup_mount_points()  # pylint: disable=E1101

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
                cgroup2_mount_point, cgroup2_controllers = self._cgroups_api.get_cgroup2_controllers()  # pylint: disable=E1101
                if cgroup2_mount_point is not None:
                    log_cgroup_info("cgroups v2 mounted at {0}.  Controllers: [{1}]", cgroup2_mount_point, cgroup2_controllers)

                #
                # check the cgroups for the agent
                #
                agent_unit_name = self._cgroups_api.get_agent_unit_name()  # pylint: disable=E1101
                cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_process_cgroup_relative_paths("self")  # pylint: disable=E1101
                expected_relative_path = os.path.join('system.slice', agent_unit_name)
                if cpu_cgroup_relative_path is None:
                    log_cgroup_info("The agent's process is not within a CPU cgroup")
                else:
                    if cpu_cgroup_relative_path != expected_relative_path:
                        log_cgroup_info("The Agent is not in the expected cgroup; will not enable cgroup monitoring. CPU relative path:[{0}] Expected:[{1}]", cpu_cgroup_relative_path, expected_relative_path)
                        return
                    cpu_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "CPUAccounting")  # pylint: disable=E1101
                    log_cgroup_info('CPUAccounting: {0}', cpu_accounting)

                if memory_cgroup_relative_path is None:
                    log_cgroup_info("The agent's process is not within a memory cgroup")
                else:
                    if memory_cgroup_relative_path != expected_relative_path:
                        log_cgroup_info("The Agent is not in the expected cgroup; will not enable cgroup monitoring. Memory relative path:[{0}] Expected:[{1}]", memory_cgroup_relative_path, expected_relative_path)
                        return
                    memory_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "MemoryAccounting")  # pylint: disable=E1101
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

        def _invoke_cgroup_operation(self, operation, error_message, on_error=None):
            """
            Ensures the given operation is invoked only if cgroups are enabled and traps any errors on the operation.
            """
            if not self.enabled():
                return None

            try:
                return operation()
            except Exception as exception:
                logger.warn("{0} Error: {1}".format(error_message, ustr(exception)))
                if on_error is not None:
                    try:
                        on_error(exception)
                    except Exception as exception:
                        logger.warn("CGroupConfigurator._invoke_cgroup_operation: {0}".format(ustr(exception)))

        def create_extension_cgroups_root(self):
            """
            Creates the container (directory/cgroup) that includes the cgroups for all extensions (/sys/fs/cgroup/*/walinuxagent.extensions)
            """
            def __impl():
                self._cgroups_api.create_extension_cgroups_root()

            self._invoke_cgroup_operation(__impl, "Failed to create a root cgroup for extensions; resource usage for extensions will not be tracked.")

        def create_extension_cgroups(self, name):
            """
            Creates and returns the cgroups for the given extension
            """
            def __impl():
                return self._cgroups_api.create_extension_cgroups(name)

            return self._invoke_cgroup_operation(__impl, "Failed to create a cgroup for extension '{0}'; resource usage will not be tracked.".format(name))

        def remove_extension_cgroups(self, name):
            """
            Deletes the cgroup for the given extension
            """
            def __impl():
                self._cgroups_api.remove_extension_cgroups(name)

            self._invoke_cgroup_operation(__impl, "Failed to delete cgroups for extension '{0}'.".format(name))

        def get_processes_in_agent_cgroup(self):
            """
            Returns an array of tuples with the PID and command line of the processes that are currently within the cgroup for the given unit.

            The return value can be None if cgroups are not enabled or if an error occurs during the operation.
            """
            def __impl():
                if self._agent_cpu_cgroup_path is None:
                    return []
                return self._cgroups_api.get_processes_in_cgroup(self._agent_cpu_cgroup_path)  # pylint: disable=E1101

            def __on_error(exception):
                #
                # Send telemetry for a small sample of errors (if any)
                #
                self._get_processes_in_agent_cgroup_error_count = self._get_processes_in_agent_cgroup_error_count + 1
                if self._get_processes_in_agent_cgroup_error_count <= 5:
                    message = "Failed to list the processes in the agent's cgroup: {0}", ustr(exception)
                    if message != self._get_processes_in_agent_cgroup_last_error:
                        add_event(op=WALAEventOperation.CGroupsDebug, message=message)
                    self._get_processes_in_agent_cgroup_last_error = message

            return self._invoke_cgroup_operation(__impl, "Failed to list the processes in the agent's cgroup.", on_error=__on_error)

        # too-many-arguments<R0913> Disabled: argument list mimics Popen's
        def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, error_code=ExtensionErrorCodes.PluginUnknownFailure):  # pylint: disable=R0913
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

    @staticmethod
    def is_agent_process(command_line):
        """
        Returns true if the given command line corresponds to a process started by the agent.

        NOTE: The function uses pattern matching to determine whether the process was spawned by the agent; this is more of a heuristic
        than an exact check.
        """
        patterns = [
            r".*waagent -daemon.*",
            r".*(WALinuxAgent-.+\.egg|waagent) -run-exthandlers",
            # The processes in the agent's cgroup are listed using systemd-cgls
            r"^systemd-cgls.*walinuxagent.*$",
            # Extensions are started using systemd-run
            r"^systemd-run --unit=.+ --scope ",
            #
            # The rest of the commands are started by the environment thread; many of them are distro-specific so this list may need
            # additions as we add support for more distros.
            #
            # *** Monitor DHCP client restart
            #
            r"^pidof (dhclient|dhclient3|systemd-networkd)",
            r"^ip route (show|add)",
            #
            # *** Enable firewall
            #
            r"^iptables --version$",
            r"^iptables .+ -t security",
            #
            # *** Monitor host name changes
            #
            r"^ifdown .+ && ifup .+",
        ]
        for p in patterns: # pylint: disable=C0103
            if re.match(p, command_line) is not None:
                return True
        return False
