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
from azurelinuxagent.common.cgroupapi import CGroupsApi
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.common.event import add_event, WALAEventOperation


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command, none of the methods in this class raise exceptions (cgroup operations should not block extensions)
    """
    class __impl(object):
        def __init__(self):
            """
            Ensures the cgroups file system is mounted and selects the correct API to interact with it
            """
            osutil = get_osutil()

            self._cgroups_supported = osutil.is_cgroups_supported()

            if self._cgroups_supported:
                self._enabled = True
                try:
                    osutil.mount_cgroups()
                    self._cgroups_api = CGroupsApi.create()
                    status = "The cgroup filesystem is ready to use"
                except Exception as e:
                    status = ustr(e)
                    self._enabled = False
            else:
                self._enabled = False
                self._cgroups_api = None
                status = "Cgroups are not supported by the platform"

            logger.info("CGroups Status: {0}".format(status))

            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.InitializeCGroups,
                is_success=self._enabled,
                message=status,
                log_event=False)

        def enabled(self):
            return self._enabled

        def enable(self):
            if not self._cgroups_supported:
                raise CGroupsException("cgroups are not supported on the current platform")

            self._enabled = True

        def disable(self):
            self._enabled = False

        def _invoke_cgroup_operation(self, operation, error_message):
            """
            Ensures the given operation is invoked only if cgroups are enabled and traps any errors on the operation.
            """
            if not self.enabled():
                return

            try:
                return operation()
            except Exception as e:
                logger.warn("{0}. Error: {1}".format(error_message, ustr(e)))

        def create_agent_cgroups(self, track_cgroups):
            """
            Creates and returns the cgroups needed to track the VM Agent
            """
            def __impl():
                cgroups = self._cgroups_api.create_agent_cgroups()

                if track_cgroups:
                    for cgroup in cgroups:
                        CGroupsTelemetry.track_cgroup(cgroup)

                return cgroups

            self._invoke_cgroup_operation(__impl, "Failed to create a cgroup for the VM Agent; resource usage for the Agent will not be tracked")

        def create_extension_cgroups_root(self):
            """
            Creates the container (directory/cgroup) that includes the cgroups for all extensions (/sys/fs/cgroup/*/walinuxagent.extensions)
            """
            def __impl():
                self._cgroups_api.create_extension_cgroups_root()

            self._invoke_cgroup_operation(__impl, "Failed to create a root cgroup for extensions; resource usage for extensions will not be tracked")

        def create_extension_cgroups(self, name):
            """
            Creates and returns the cgroups for the given extension
            """
            def __impl():
                return self._cgroups_api.create_extension_cgroups(name)

            return self._invoke_cgroup_operation(__impl, "Failed to create a cgroup for extension '{0}'; resource usage will not be tracked".format(name))

        def remove_extension_cgroups(self, name):
            """
            Deletes the cgroup for the given extension
            """
            def __impl():
                cgroups = self._cgroups_api.remove_extension_cgroups(name)
                return cgroups

            self._invoke_cgroup_operation(__impl, "Failed to delete cgroups for extension '{0}'.".format(name))

        def start_extension_command(self, extension_name, command, shell, cwd, env, stdout, stderr):
            """
            Starts a command (install/enable/etc) for an extension and adds the command's PID to the extension's cgroup
            :param extension_name: The extension executing the command
            :param command: The command to invoke
            :param cwd: The working directory for the command
            :param env:  The environment to pass to the command's process
            :param stdout: File object to redirect stdout to
            :param stderr: File object to redirect stderr to
            """
            if not self.enabled():
                process = subprocess.Popen(
                    command,
                    shell=shell,
                    cwd=cwd,
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                    preexec_fn=os.setsid)
            else:
                process, extension_cgroups = self._cgroups_api.start_extension_command(
                    extension_name,
                    command,
                    shell=shell,
                    cwd=cwd,
                    env=env,
                    stdout=stdout,
                    stderr=stderr)

                try:
                    for cgroup in extension_cgroups:
                        CGroupsTelemetry.track_cgroup(cgroup)
                except Exception as e:
                    logger.warn("Cannot add cgroup '{0}' to tracking list; resource usage will not be tracked. Error: {1}".format(cgroup.path, ustr(e)))

            return process

    # unique instance for the singleton (TODO: find a better pattern for a singleton)
    _instance = None

    @staticmethod
    def get_instance():
        if CGroupConfigurator._instance is None:
            CGroupConfigurator._instance = CGroupConfigurator.__impl()
        return CGroupConfigurator._instance
