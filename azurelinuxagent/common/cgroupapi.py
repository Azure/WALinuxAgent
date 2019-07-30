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
import time
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.processutil import read_output
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

CGROUPS_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
CGROUP_CONTROLLERS = ["cpu", "memory"]
VM_AGENT_CGROUP_NAME = "walinuxagent.service"
EXTENSIONS_ROOT_CGROUP_NAME = "walinuxagent.extensions"
UNIT_FILES_FILE_SYSTEM_PATH = "/etc/systemd/system"


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

    def get_extension_cgroups(self, extension_name):
        raise NotImplementedError()

    def start_extension_command(self, extension_name, command, shell, cwd, env, stdout, stderr):
        raise NotImplementedError()

    def cleanup_old_cgroups(self):
        raise NotImplementedError()

    @staticmethod
    def _get_extension_cgroup_name(extension_name):
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return extension_name.replace('-', '_')

    @staticmethod
    def create():
        """
        Factory method to create the correct API for the current platform
        """
        return SystemdCgroupsApi() if CGroupsApi._is_systemd() else FileSystemCgroupsApi()

    @staticmethod
    def _is_systemd():
        """
        Determine if systemd is managing system services. If this process (presumed to be the agent) is in a CPU cgroup
        that looks like one created by systemd, we can assume systemd is in use.

        TODO: We need to re-evaluate whether this the right logic to determine if Systemd is managing cgroups.

        :return: True if systemd is managing system services
        :rtype: Bool
        """
        controller_id = CGroupsApi._get_controller_id('cpu')
        current_process_cgroup_path = CGroupsApi._get_current_process_cgroup_relative_path(controller_id)
        is_systemd = current_process_cgroup_path == 'system.slice/walinuxagent.service'

        return is_systemd

    @staticmethod
    def _get_current_process_cgroup_relative_path(controller_id):
        """
        Get the cgroup path "suffix" for this process for the given controller. The leading "/" is always stripped,
        so the suffix is suitable for passing to os.path.join(). (If the process is in the root cgroup, an empty
        string is returned, and os.path.join() will still do the right thing.)
        """
        cgroup_paths = fileutil.read_file("/proc/self/cgroup")
        for entry in cgroup_paths.splitlines():
            fields = entry.split(':')
            if fields[0] == controller_id:
                return fields[2].lstrip(os.path.sep)
        raise CGroupsException("This process belongs to no cgroup for controller ID {0}".format(controller_id))


    @staticmethod
    def _get_controller_id(controller):
        """
        Get the ID for a given cgroup controller
        """
        cgroup_states = fileutil.read_file("/proc/cgroups")
        for entry in cgroup_states.splitlines():
            fields = entry.split('\t')
            if fields[0] == controller:
                return fields[1]
        raise CGroupsException("Cgroup controller {0} not found in /proc/cgroups".format(controller))

    @staticmethod
    def _foreach_controller(operation, message):
        """
        Executes the given operation on all controllers that need to be tracked; outputs 'message' if the controller
        is not mounted or if an error occurs in the operation
        """
        mounted_controllers = os.listdir(CGROUPS_FILE_SYSTEM_ROOT)

        for controller in CGROUP_CONTROLLERS:
            try:
                if controller not in mounted_controllers:
                    logger.warn('Cgroup controller "{0}" is not mounted. {1}'.format(controller, message))
                else:
                    operation(controller)
            except Exception as e:
                logger.warn('Error in cgroup controller "{0}": {1}. {2}'.format(controller, ustr(e), message))


class FileSystemCgroupsApi(CGroupsApi):
    """
    Cgroups interface using the cgroups file system directly
    """
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
    def _get_extension_cgroups_root_path(controller):
        return os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, EXTENSIONS_ROOT_CGROUP_NAME)

    def _get_extension_cgroup_path(self, controller, extension_name):
        extensions_root = self._get_extension_cgroups_root_path(controller)

        if not os.path.exists(extensions_root):
            logger.warn("Root directory {0} does not exist.".format(extensions_root))

        cgroup_name = self._get_extension_cgroup_name(extension_name)

        return os.path.join(extensions_root, cgroup_name)

    def _create_extension_cgroup(self, controller, extension_name):
        return CGroup.create(self._get_extension_cgroup_path(controller, extension_name),
                             controller, extension_name)

    @staticmethod
    def _add_process_to_cgroup(pid, cgroup_path):
        tasks_file = os.path.join(cgroup_path, 'cgroup.procs')
        fileutil.append_file(tasks_file, "{0}\n".format(pid))
        logger.info("Added PID {0} to cgroup {1}".format(pid, cgroup_path))

    def cleanup_old_cgroups(self):
        # Old daemon versions (2.2.31-2.2.40) wrote their PID to the WALinuxAgent/WALinuxAgent cgroup.
        # Starting from version 2.2.41, we track the agent service in walinuxagent.service. This method
        # cleans up the old behavior by moving the daemon's PID to the new cgroup and deleting the old cgroup.
        daemon_pid_file = get_agent_pid_file_path()
        daemon_pid = fileutil.read_file(daemon_pid_file)

        def cleanup_old_controller(controller):
            old_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, "WALinuxAgent", "WALinuxAgent")
            new_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, VM_AGENT_CGROUP_NAME)

            if not os.path.isdir(old_path):
                return

            contents = fileutil.read_file(os.path.join(old_path, "cgroup.procs"))

            if daemon_pid in contents:
                fileutil.append_file(os.path.join(new_path, "cgroup.procs"), daemon_pid)
                shutil.rmtree(old_path, ignore_errors=True)

        self._foreach_controller(cleanup_old_controller, "Failed to update the tracking of the daemon; resource usage "
                                                         "of the agent will not include the daemon process.")

    def create_agent_cgroups(self):
        """
        Creates a cgroup for the VM Agent in each of the controllers we are tracking; returns the created cgroups.
        """
        cgroups = []

        pid = int(os.getpid())

        def create_cgroup(controller):
            path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, VM_AGENT_CGROUP_NAME)

            if not os.path.isdir(path):
                FileSystemCgroupsApi._try_mkdir(path)
                logger.info("Created cgroup {0}".format(path))

            self._add_process_to_cgroup(pid, path)

            cgroups.append(CGroup.create(path, controller, VM_AGENT_CGROUP_NAME))

        self._foreach_controller(create_cgroup, 'Failed to create a cgroup for the VM Agent; resource usage will not be tracked')

        if len(cgroups) == 0:
            raise CGroupsException("Failed to create any cgroup for the VM Agent")

        return cgroups

    def create_extension_cgroups_root(self):
        """
        Creates the directory within the cgroups file system that will contain the cgroups for the extensions.
        """
        def create_cgroup(controller):
            path = self._get_extension_cgroups_root_path(controller)

            if not os.path.isdir(path):
                FileSystemCgroupsApi._try_mkdir(path)
                logger.info("Created {0}".format(path))

        self._foreach_controller(create_cgroup, 'Failed to create a root cgroup for extensions')

    def create_extension_cgroups(self, extension_name):
        """
        Creates a cgroup for the given extension in each of the controllers we are tracking; returns the created cgroups.
        """
        cgroups = []

        def create_cgroup(controller):
            cgroup = self._create_extension_cgroup(controller, extension_name)

            if not os.path.isdir(cgroup.path):
                FileSystemCgroupsApi._try_mkdir(cgroup.path)
                logger.info("Created cgroup {0}".format(cgroup.path))

            cgroups.append(cgroup)

        self._foreach_controller(create_cgroup, 'Failed to create a cgroup for extension {0}'.format(extension_name))

        return cgroups

    def remove_extension_cgroups(self, extension_name):
        """
        Deletes the cgroups for the given extension.
        """
        def remove_cgroup(controller):
            path = self._get_extension_cgroup_path(controller, extension_name)

            if os.path.exists(path):
                try:
                    os.rmdir(path)
                    logger.info('Deleted cgroup "{0}".'.format(path))
                except OSError as exception:
                    if exception.errno == 16:  # [Errno 16] Device or resource busy
                        logger.warn('CGroup "{0}" still has active tasks; will not remove it.'.format(path))

        self._foreach_controller(remove_cgroup, 'Failed to delete cgroups for extension {0}'.format(extension_name))

    def get_extension_cgroups(self, extension_name):
        """
        Returns the cgroups for the given extension.
        """

        cgroups = []

        def get_cgroup(controller):
            cgroup = self._create_extension_cgroup(controller, extension_name)
            cgroups.append(cgroup)

        self._foreach_controller(get_cgroup, 'Failed to retrieve cgroups for extension {0}'.format(extension_name))

        return cgroups

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
        try:
            extension_cgroups = self.create_extension_cgroups(extension_name)
        except Exception as exception:
            extension_cgroups = []
            logger.warn("Failed to create cgroups for extension '{0}'; resource usage will not be tracked. Error: {1}".format(extension_name, ustr(exception)))

        def pre_exec_function():
            os.setsid()

            try:
                pid = os.getpid()

                for cgroup in extension_cgroups:
                    try:
                        self._add_process_to_cgroup(pid, cgroup.path)
                    except Exception as exception:
                        logger.warn("Failed to add PID {0} to the cgroups for extension '{1}'. Resource usage will not be tracked. Error: {2}".format(pid, extension_name, ustr(exception)))
            except Exception as e:
                logger.warn("Failed to add extension {0} to its cgroup. Resource usage will not be tracked. Error: {1}".format(extension_name, ustr(e)))

        process = subprocess.Popen(
            command,
            shell=shell,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=pre_exec_function)

        return process, extension_cgroups


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """

    @staticmethod
    def create_and_start_unit(unit_filename, unit_contents):
        try:
            unit_path = os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, unit_filename)
            fileutil.write_file(unit_path, unit_contents)
            shellutil.run_get_output("systemctl daemon-reload")
            shellutil.run_get_output("systemctl start {0}".format(unit_filename))
        except Exception as e:
            raise CGroupsException("Failed to create and start {0}. Error: {1}".format(unit_filename, ustr(e)))

    @staticmethod
    def _get_extensions_slice_root_name():
        return "system-{0}.slice".format(EXTENSIONS_ROOT_CGROUP_NAME)

    def _get_extension_slice_name(self, extension_name):
        return "system-{0}-{1}.slice".format(EXTENSIONS_ROOT_CGROUP_NAME, self._get_extension_cgroup_name(extension_name))

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

            return [CGroup.create(cpu_cgroup_path, 'cpu', VM_AGENT_CGROUP_NAME),
                    CGroup.create(memory_cgroup_path, 'memory', VM_AGENT_CGROUP_NAME)]
        except Exception as e:
            raise CGroupsException("Failed to get paths of agent's cgroups. Error: {0}".format(ustr(e)))

    def create_extension_cgroups_root(self):
        unit_contents = """
[Unit]
Description=Slice for walinuxagent extensions
DefaultDependencies=no
Before=slices.target
Requires=system.slice
After=system.slice"""
        unit_filename = self._get_extensions_slice_root_name()
        self.create_and_start_unit(unit_filename, unit_contents)
        logger.info("Created slice for walinuxagent extensions {0}".format(unit_filename))

    def create_extension_cgroups(self, extension_name):
        # TODO: The slice created by this function is not used currently. We need to create the extension scopes within
        #  this slice and use the slice to monitor the cgroups. Also see comment in get_extension_cgroups.
        # the slice.
        unit_contents = """
[Unit]
Description=Slice for extension {0}
DefaultDependencies=no
Before=slices.target
Requires=system-{1}.slice
After=system-{1}.slice""".format(extension_name, EXTENSIONS_ROOT_CGROUP_NAME)
        unit_filename = self._get_extension_slice_name(extension_name)
        self.create_and_start_unit(unit_filename, unit_contents)
        logger.info("Created slice for {0}".format(unit_filename))

        return self.get_extension_cgroups(extension_name)

    def remove_extension_cgroups(self, extension_name):
        # For transient units, cgroups are released automatically when the unit stops, so it is sufficient
        # to call stop on them. Persistent cgroups are released when the unit is disabled and its configuration
        # file is deleted.
        # The assumption is that this method is called after the extension has been uninstalled. For now, since
        # we're running extensions within transient scopes which clean up after they finish running, no removal
        # of units is needed. In the future, when the extension is running under its own slice,
        # the following clean up is needed.
        unit_filename = self._get_extension_slice_name(extension_name)
        try:
            unit_path = os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, unit_filename)
            shellutil.run_get_output("systemctl stop {0}".format(unit_filename))
            fileutil.rm_files(unit_path)
            shellutil.run_get_output("systemctl daemon-reload")
        except Exception as e:
            raise CGroupsException("Failed to remove {0}. Error: {1}".format(unit_filename, ustr(e)))

    def get_extension_cgroups(self, extension_name):
        # TODO: The slice returned by this function is not used currently. We need to create the extension scopes within
        #  this slice and use the slice to monitor the cgroups. Also see comment in create_extension_cgroups.
        slice_name = self._get_extension_cgroup_name(extension_name)

        cgroups = []

        def create_cgroup(controller):
            cpu_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, 'system.slice', slice_name)
            cgroups.append(CGroup.create(cpu_cgroup_path, controller, extension_name))

        self._foreach_controller(create_cgroup, 'Cannot retrieve cgroup for extension {0}; resource usage will not be tracked.'.format(extension_name))

        return cgroups

    def start_extension_command(self, extension_name, command, shell, cwd, env, stdout, stderr):
        scope_name = "{0}_{1}".format(self._get_extension_cgroup_name(extension_name), uuid.uuid4())

        process = subprocess.Popen(
            "systemd-run --unit={0} --scope {1}".format(scope_name, command),
            shell=shell,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=os.setsid)

        # Wait a bit and check if we completed with error
        time.sleep(1)
        return_code = process.poll()

        if return_code is not None and return_code != 0:
            process_output = read_output(stdout, stderr)

            # When systemd-run successfully invokes a command, thereby creating its unit, it will output the
            # unit's name. Since the scope name is only known to systemd-run, and not to the extension itself,
            # if scope_name appears in the output, we are certain systemd-run managed to run.
            if scope_name not in process_output:
                add_event(AGENT_NAME,
                          version=CURRENT_VERSION,
                          op=WALAEventOperation.InvokeCommandUsingSystemd,
                          is_success=False,
                          message='Failed to run systemd-run for unit {0}.scope. '
                                  'Process exited with code {1} and output {2}'.format(scope_name,
                                                                                       return_code,
                                                                                       process_output))
                # Reset the stdout and stderr
                stdout.truncate(0)
                stderr.truncate(0)

                # Try starting the process without systemd-run
                process = subprocess.Popen(
                    command,
                    shell=shell,
                    cwd=cwd,
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                    preexec_fn=os.setsid)

                return process, []

        cgroups = []

        logger.info("Started extension using scope '{0}'", scope_name)

        def create_cgroup(controller):
            cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, 'system.slice', scope_name + ".scope")
            cgroups.append(CGroup.create(cgroup_path, controller, extension_name))

        self._foreach_controller(create_cgroup, 'Cannot create cgroup for extension {0}; resource usage will not be tracked.'.format(extension_name))

        return process, cgroups

    def cleanup_old_cgroups(self):
        # No cleanup needed from the old daemon in the systemd case.
        pass
