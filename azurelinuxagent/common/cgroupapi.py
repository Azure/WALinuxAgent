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

import errno
import os
import shutil

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil

CGROUPS_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
CGROUP_CONTROLLERS = ["cpu", "memory"]
VM_AGENT_CGROUP_NAME = "walinuxagent.service"
EXTENSIONS_ROOT_CGROUP_NAME = "walinuxagent.extensions"

class CGroupsApi(object):
    """
    Interface for the cgroups API
    """
    def create_agent_cgroups(self):
        raise NotImplementedError()

    def create_extension_cgroups_root(self):
        raise NotImplementedError()

    def create_extension_cgroups(self, extension_name):
        raise NotImplementedError()

    def remove_extension_cgroups(self, extension_name):
        raise NotImplementedError()


class FileSystemCgroupsApi(CGroupsApi):
    """
    Cgroups interface using the cgroups file system directly
    """
    _osutil = get_osutil()

    @staticmethod
    def _try_mkdir(path):
        """
        Try to create a directory, recursively. If it already exists as such, do nothing. Raise the appropriate
        exception should an error occur.

        :param path: str
        """
        if not os.path.isdir(path):
            try:
                os.makedirs(path, 0o755)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    if not os.path.isdir(path):
                        raise CGroupsException("Create directory for cgroup {0}: normal file already exists with that name".format(path))
                    else:
                        pass  # There was a race to create the directory, but it's there now, and that's fine
                elif e.errno == errno.EACCES:
                    # This is unexpected, as the agent runs as root
                    raise CGroupsException("Create directory for cgroup {0}: permission denied".format(path))
                else:
                    raise

    @staticmethod
    def _foreach_controller(operation, message):
        """
        Executes the given operation on all controllers that need to be tracked; outputs 'message' if the controller is not mounted.
        """
        mounted_controllers = os.listdir(CGROUPS_FILE_SYSTEM_ROOT)

        for controller in CGROUP_CONTROLLERS:
            if controller not in mounted_controllers:
                logger.warn('Controller "{0}" is not mounted. {1}'.format(controller, message))
            else:
                operation(controller)

    @staticmethod
    def _get_extension_cgroups_root_path(controller):
        return os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, EXTENSIONS_ROOT_CGROUP_NAME)

    def _get_extension_cgroup_path(self, controller, extension_name):
        extensions_root = self._get_extension_cgroups_root_path(controller)

        if not os.path.exists(extensions_root):
            logger.warn("Root directory {0} does not exist.".format(extensions_root))

        # '-' has a special meaning within systemd unit names; for consistency we also replace with '_' here
        cgroup_name = extension_name.replace('-', '_')

        return os.path.join(extensions_root, cgroup_name)

    @staticmethod
    def _add_process_to_cgroup(pid, cgroup_path):
        tasks_file = os.path.join(cgroup_path, 'cgroup.procs')
        fileutil.append_file(tasks_file, "{0}\n".format(pid))
        logger.info("Added PID {0} to cgroup {1}".format(pid, cgroup_path))

    def create_agent_cgroups(self):
        """
        Creates a cgroup for the VM Agent in each of the controllers we are tracking; returns the created cgroups.
        """
        cgroup_paths = []

        pid = int(os.getpid())

        def create_cgroup(controller):
            try:
                path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, VM_AGENT_CGROUP_NAME)

                if not os.path.isdir(path):
                    FileSystemCgroupsApi._try_mkdir(path)
                    logger.info("Created cgroup {0}".format(path))

                self._add_process_to_cgroup(pid, path)

                cgroup_paths.append(path)

            except Exception as e:
                logger.warn('Cannot create "{0}" cgroup for the agent. Error: {1}'.format(controller, ustr(e)))

        self._foreach_controller(create_cgroup, 'Will not create a cgroup for the VM Agent')

        if len(cgroup_paths) == 0:
            raise CGroupsException("Failed to create any cgroup for the VM Agent")

        return cgroup_paths

    def create_extension_cgroups_root(self):
        """
        Creates the directory within the cgroups file system that will contain the cgroups for the extensions.
        """
        def create_cgroup(controller):
            path = self._get_extension_cgroups_root_path(controller)

            if not os.path.isdir(path):
                FileSystemCgroupsApi._try_mkdir(path)
                logger.info("Created {0}".format(path))

        self._foreach_controller(create_cgroup, 'Will not create a root cgroup for extensions')

    def create_extension_cgroups(self, extension_name):
        """
        Creates a cgroup for the given extension in each of the controllers we are tracking; returns the created cgroups.
        """
        cgroup_paths = []

        def create_cgroup(controller):
            path = self._get_extension_cgroup_path(controller, extension_name)

            if not os.path.isdir(path):
                FileSystemCgroupsApi._try_mkdir(path)
                logger.info("Created cgroup {0}".format(path))

            cgroup_paths.append(path)

        self._foreach_controller(create_cgroup, 'Will not create a cgroup for extension {0}'.format(extension_name))

        return cgroup_paths

    def remove_extension_cgroups(self, extension_name):
        """
        Deletes the cgroups for the given extension.
        """
        def remove_cgroup(controller):
            path = self._get_extension_cgroup_path(controller, extension_name)

            shutil.rmtree(path)

        self._foreach_controller(remove_cgroup, 'Failed to delete cgroups for extension {0}'.format(extension_name))

    def get_extension_cgroups(self, extension_name):
        """
        Returns the cgroups for the given extension.
        """
        cgroup_paths = []

        def get_cgroup(controller):
            path = self._get_extension_cgroup_path(controller, extension_name)
            cgroup_paths.append(path)

        self._foreach_controller(get_cgroup, 'Failed to retrieve cgroups for extension {0}'.format(extension_name))

        return cgroup_paths

    def add_process_to_extension_cgroup(self, extension_name, pid):
        """
        Adds the given PID to the cgroups for the given extension
        """
        def add_pid(controller):
            path = self._get_extension_cgroup_path(controller, extension_name)
            self._add_process_to_cgroup(pid, path)

        self._foreach_controller(add_pid, 'Failed to add PID {0} to the cgroups for extension {1}'.format(pid, extension_name))


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """
    def create_agent_cgroups(self):
        pass

    def create_extension_cgroups_root(self):
        pass

    def create_extension_cgroups(self, extension_name):
        pass

    def remove_extension_cgroups(self, extension_name):
        pass
