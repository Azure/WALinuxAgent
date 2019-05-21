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
import subprocess

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil, shellutil

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

    def start_extension_command(self, extension_name, command, cwd, env, stdout, stderr):
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

    def start_extension_command(self, extension_name, command, cwd, env, stdout, stderr):
        """
        Starts a command (install/enable/etc) for an extension and adds the command's PID to the extension's cgroup
        :param extension_name: The extension executing the command
        :param command: The command to invoke
        :param cwd: The working directory for the command
        :param env:  The environment to pass to the command's process
        :param stdout: File object to redirect stdout to
        :param stderr: File object to redirect stderr to
        """
        def pre_exec_function():
            os.setsid()

            try:
                pid = os.getpid()

                def add_pid(controller):
                    path = self._get_extension_cgroup_path(controller, extension_name)
                    self._add_process_to_cgroup(pid, path)

                self._foreach_controller(add_pid, 'Failed to add PID {0} to the cgroups for extension {1}. Resource usage will not be tracked.'.format(pid, extension_name))

            except Exception as e:
                logger.warn("Failed to add extension {0} to its cgroup. Resource usage will not be tracked. Error: {1}".format(extension_name, ustr(e)))

        process = subprocess.Popen(
            command,
            shell=True,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=pre_exec_function)

        return process


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """

    @staticmethod
    def create_and_start_unit(unit_filename, unit_contents):
        try:
            fileutil.write_file("/etc/systemd/system/{0}".format(unit_filename), unit_contents)
            shellutil.run_get_output("systemctl daemon-reload")
            shellutil.run_get_output("systemctl start {0}".format(unit_filename))
        except Exception as e:
            logger.warn("Failed to create and start {0}. Error: {1}".format(unit_filename, ustr(e)))

    @staticmethod
    def _get_extension_unit_root_path():
        return "system-{0}.slice".format(EXTENSIONS_ROOT_CGROUP_NAME)

    @staticmethod
    def _get_extension_unit_path(extension_name):
        return "system-walinuxagent.extensions-{0}.slice".format(extension_name.replace('-', '_'))

    def create_agent_cgroups(self):
        try:
            cgroup_unit = None
            cgroup_paths = fileutil.read_file("/proc/self/cgroup")
            for entry in cgroup_paths.splitlines():
                fields = entry.split(':')
                if fields[1] == "name=systemd":
                    cgroup_unit = fields[2].lstrip(os.path.sep)

            cpu_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, 'cpu', cgroup_unit)
            memory_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, 'memory', cgroup_unit)

            return [cpu_cgroup_path, memory_cgroup_path]
        except Exception as e:
            logger.warn("Failed to get paths of agent's cgroups. Error: {0}".format(ustr(e)))

    def create_extension_cgroups_root(self):
        unit_contents = """[Unit]
Description=Slice for WALinuxAgent extensions
DefaultDependencies=no
Before=slices.target
Requires=system.slice
After=system.slice"""
        unit_filename = self._get_extension_unit_root_path()
        self.create_and_start_unit(unit_filename, unit_contents)
        logger.info("Created and started {0}".format(unit_filename))

    def create_extension_cgroups(self, extension_name):
        # TODO: revisit if we need this code now (not used until we interact with the D-bus API and run the
        #  extension scopes within their designated slice)
        unit_contents = """[Unit]
Description=Slice for extension {0}
DefaultDependencies=no
Before=slices.target
Requires=system-{1}.slice
After=system-{1}.slice""".format(extension_name, EXTENSIONS_ROOT_CGROUP_NAME)
        unit_filename = self._get_extension_unit_path(extension_name)
        self.create_and_start_unit(unit_filename, unit_contents)
        logger.info("Created and started {0}".format(unit_filename))

        # TODO: revisit if the cgroup (path) creation should happen here or later
        scope_name = extension_name.replace('-', '_')
        cpu_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, 'cpu', 'system.slice', scope_name)
        memory_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, 'memory', 'system.slice', scope_name)

        return [cpu_cgroup_path, memory_cgroup_path]

    def remove_extension_cgroups(self, extension_name):
        # In the future, when the extension is running under the extensions slice:
        # unit_filename = self._get_extension_unit_path()

        # Current implementation when extensions are running within a scope on the system level
        unit_filename = "{0}.scope".format(extension_name.replace('-', '_'))
        try:
            # For transient units, cgroups are released automatically when the unit stops, so it is sufficient
            # to call stop on them. Persistent cgroups are released when the unit is disabled and its configuration
            # file is deleted.
            shellutil.run_get_output("systemctl stop {0}".format(unit_filename))
            fileutil.rm_files("/etc/systemd/system/{0}".format(unit_filename))
            shellutil.run_get_output("systemctl daemon-reload")
        except Exception as e:
            logger.warn("Failed to remove {0}. Error: {1}".format(unit_filename, ustr(e)))

    def start_extension_command(self, extension_name, command, cwd, env, stdout, stderr):
        def pre_exec_function():
            os.setsid()

        process = subprocess.Popen(
            "systemd-run --unit={0} --scope {1}".format(extension_name.replace('-', '_'), command),
            shell=True,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=pre_exec_function)

        return process

