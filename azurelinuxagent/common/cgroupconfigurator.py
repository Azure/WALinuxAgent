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
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command, none of the methods in this class raise exceptions (cgroup operations should not block extensions)
    """
    class __impl(object):
        def __init__(self):
            self._initialized = False
            self._cgroups_supported = False
            self._cgroups_enabled = False
            self._cgroups_api = None

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

                def log_cgroup_warn(format_string, *args):
                    message = format_string.format(*args)
                    logger.warn(message)
                    add_event(op=WALAEventOperation.CGroupsInfo, message=message, is_success=False, log_event=False)

                log_cgroup_info("systemd version: {0}", self._cgroups_api.get_systemd_version())

                #
                # Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent.  When running
                # under systemd this could produce invalid resource usage data. Do not enable cgroups under this condition.
                #
                legacy_cgroups = self._cgroups_api.cleanup_legacy_cgroups()

                if legacy_cgroups > 0:
                    log_cgroup_warn("The daemon's PID was added to a legacy cgroup; will not monitor resource usage.")
                    return

                #
                # check v1 controllers
                #
                cpu_controller_root, memory_controller_root = self._cgroups_api.get_cpu_and_memory_mount_points()

                if cpu_controller_root is not None:
                    logger.info("The CPU cgroup controller is mounted at {0}", cpu_controller_root)
                else:
                    log_cgroup_warn("The CPU cgroup controller is not mounted")

                if memory_controller_root is not None:
                    logger.info("The memory cgroup controller is mounted at {0}", memory_controller_root)
                else:
                    log_cgroup_warn("The memory cgroup controller is not mounted")

                #
                # check v2 controllers
                #
                cgroup2_mountpoint, cgroup2_controllers = self._cgroups_api.get_cgroup2_controllers()
                if cgroup2_mountpoint is not None:
                    log_cgroup_warn("cgroups v2 mounted at {0}.  Controllers: [{1}]", cgroup2_mountpoint, cgroup2_controllers)

                #
                # check the cgroups for the agent
                #
                agent_unit_name = get_osutil().get_service_name() + ".service"
                cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_cpu_and_memory_cgroup_relative_paths_for_process("self")
                if cpu_cgroup_relative_path is None:
                    log_cgroup_warn("The agent's process is not within a CPU cgroup")
                else:
                    cpu_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "CPUAccounting")
                    log_cgroup_info('CPUAccounting: {0}', cpu_accounting)

                if memory_cgroup_relative_path is None:
                    log_cgroup_warn("The agent's process is not within a memory cgroup")
                else:
                    memory_accounting = self._cgroups_api.get_unit_property(agent_unit_name, "MemoryAccounting")
                    log_cgroup_info('MemoryAccounting: {0}', memory_accounting)

                #
                # All good, enable cgroups and start monitoring the agent
                #
                self._cgroups_enabled = True

                if cpu_controller_root is None or cpu_cgroup_relative_path is None:
                    logger.info("Will not track CPU for the agent's cgroup")
                else:
                    cpu_cgroup_path = os.path.join(cpu_controller_root, cpu_cgroup_relative_path)
                    CGroupsTelemetry.track_cgroup(CpuCgroup(agent_unit_name, cpu_cgroup_path))

                if memory_controller_root is None or memory_cgroup_relative_path is None:
                    logger.info("Will not track memory for the agent's cgroup")
                else:
                    memory_cgroup_path = os.path.join(memory_controller_root, memory_cgroup_relative_path)
                    CGroupsTelemetry.track_cgroup(MemoryCgroup(agent_unit_name, memory_cgroup_path))

            except Exception as e:
                message = "Error initializing cgroups: {0}".format(ustr(e))
                logger.warn(message)
                add_event(op=WALAEventOperation.CGroupsInitialize, is_success=False, message=message, log_event=False)
            finally:
                self._initialized = True

        def enabled(self):
            return self._cgroups_enabled

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
                return

            try:
                return operation()
            except Exception as e:
                logger.warn("{0} Error: {1}".format(error_message, ustr(e)))
                if on_error is not None:
                    try:
                        on_error(e)
                    except Exception as ex:
                        logger.warn("CGroupConfigurator._invoke_cgroup_operation: {0}".format(ustr(e)))

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
                cgroups = self._cgroups_api.remove_extension_cgroups(name)
                return cgroups

            self._invoke_cgroup_operation(__impl, "Failed to delete cgroups for extension '{0}'.".format(name))

        def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr,
                                    error_code=ExtensionErrorCodes.PluginUnknownFailure):
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
                process = subprocess.Popen(command,
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
                extension_cgroups, process_output = self._cgroups_api.start_extension_command(extension_name,
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
            CGroupConfigurator._instance = CGroupConfigurator.__impl()
        return CGroupConfigurator._instance
