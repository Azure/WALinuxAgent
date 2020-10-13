# -*- coding: utf-8 -*-
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
import re
import shutil
import subprocess
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CGroup, CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import CGroupsException, ExtensionErrorCodes, ExtensionError, ExtensionOperationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion, read_output, \
    TELEMETRY_MESSAGE_MAX_LEN
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_distro

CGROUPS_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
CGROUP_CONTROLLERS = ["cpu", "memory"]
VM_AGENT_CGROUP_NAME = "walinuxagent.service"
EXTENSIONS_ROOT_CGROUP_NAME = "walinuxagent.extensions"
UNIT_FILES_FILE_SYSTEM_PATH = "/etc/systemd/system"
SYSTEMD_RUN_PATH = "/run/systemd/system/"


class CGroupsApi(object):
    """
    Interface for the cgroups API
    """
    def create_extension_cgroups_root(self):
        raise NotImplementedError()

    def create_extension_cgroups(self, extension_name):
        raise NotImplementedError()

    def remove_extension_cgroups(self, extension_name):
        raise NotImplementedError()

    def get_extension_cgroups(self, extension_name):
        raise NotImplementedError()

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, error_code): # pylint: disable=R0913
        raise NotImplementedError()

    def cleanup_legacy_cgroups(self):
        raise NotImplementedError()

    @staticmethod
    def cgroups_supported():
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            return False
        return distro_name.lower() == 'ubuntu' and distro_version.major >= 16

    @staticmethod
    def track_cgroups(extension_cgroups):
        try:
            for cgroup in extension_cgroups:
                CGroupsTelemetry.track_cgroup(cgroup)
        except Exception as e: # pylint: disable=C0103
            logger.warn("Cannot add cgroup '{0}' to tracking list; resource usage will not be tracked. "
                        "Error: {1}".format(cgroup.path, ustr(e)))

    @staticmethod
    def _get_extension_cgroup_name(extension_name):
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return extension_name.replace('-', '_')

    @staticmethod
    def create():
        """
        Factory method to create the correct API for the current platform
        """
        return SystemdCgroupsApi() if CGroupsApi.is_systemd() else FileSystemCgroupsApi()

    @staticmethod
    def is_systemd():
        """
        Determine if systemd is managing system services; the implementation follows the same strategy as, for example,
        sd_booted() in libsystemd, or /usr/sbin/service
        """
        return os.path.exists(SYSTEMD_RUN_PATH)

    @staticmethod
    def _foreach_controller(operation, message):
        """
        Executes the given operation on all controllers that need to be tracked; outputs 'message' if the controller
        is not mounted or if an error occurs in the operation
        :return: Returns a list of error messages or an empty list if no errors occurred
        """
        mounted_controllers = os.listdir(CGROUPS_FILE_SYSTEM_ROOT)

        for controller in CGROUP_CONTROLLERS:
            try:
                if controller not in mounted_controllers:
                    logger.warn('Cgroup controller "{0}" is not mounted. {1}', controller, message)
                else:
                    operation(controller)
            except Exception as e: # pylint: disable=C0103
                logger.warn('Error in cgroup controller "{0}": {1}. {2}', controller, ustr(e), message)

    @staticmethod
    def _foreach_legacy_cgroup(operation):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. Also,
        when running under systemd, the PIDs should not be explicitly moved to the cgroup filesystem. The older daemons would
        incorrectly do that under certain conditions.

        This method checks for the existence of the legacy cgroups and, if the daemon's PID has been added to them, executes the
        given operation on the cgroups. After this check, the method attempts to remove the legacy cgroups.

        :param operation:
            The function to execute on each legacy cgroup. It must take 2 arguments: the controller and the daemon's PID
        """
        legacy_cgroups = []
        for controller in ['cpu', 'memory']:
            cgroup = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, "WALinuxAgent", "WALinuxAgent")
            if os.path.exists(cgroup):
                logger.info('Found legacy cgroup {0}', cgroup)
                legacy_cgroups.append((controller, cgroup))

        try:
            for controller, cgroup in legacy_cgroups:
                procs_file = os.path.join(cgroup, "cgroup.procs")

                if os.path.exists(procs_file):
                    procs_file_contents = fileutil.read_file(procs_file).strip()
                    daemon_pid = fileutil.read_file(get_agent_pid_file_path()).strip()

                    if daemon_pid in procs_file_contents:
                        operation(controller, daemon_pid)
        finally:
            for _, cgroup in legacy_cgroups:
                logger.info('Removing {0}', cgroup)
                shutil.rmtree(cgroup, ignore_errors=True)
        return len(legacy_cgroups)


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
            except OSError as e: # pylint: disable=C0103
                if e.errno == errno.EEXIST:
                    if not os.path.isdir(path): # pylint: disable=R1720
                        raise CGroupsException("Create directory for cgroup {0}: normal file already exists with that name".format(path))
                    else:
                        pass  # There was a race to create the directory, but it's there now, and that's fine
                elif e.errno == errno.EACCES:
                    # This is unexpected, as the agent runs as root
                    raise CGroupsException("Create directory for cgroup {0}: permission denied".format(path))
                else:
                    raise

    @staticmethod
    def _get_agent_cgroup_path(controller):
        return os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, VM_AGENT_CGROUP_NAME)

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
        return CGroup.create(self._get_extension_cgroup_path(controller, extension_name), controller, extension_name)

    @staticmethod
    def _add_process_to_cgroup(pid, cgroup_path):
        tasks_file = os.path.join(cgroup_path, 'cgroup.procs')
        fileutil.append_file(tasks_file, "{0}\n".format(pid))
        logger.info("Added PID {0} to cgroup {1}".format(pid, cgroup_path))

    @staticmethod
    def mount_cgroups():
        def cgroup_path(tail=""):
            return os.path.join(CGROUPS_FILE_SYSTEM_ROOT, tail).rstrip(os.path.sep)

        try:
            osutil = get_osutil()
            path = cgroup_path()
            if not os.path.exists(path):
                fileutil.mkdir(path)
                osutil.mount(device='cgroup_root',
                           mount_point=path, 
                           option="-t tmpfs", 
                           chk_err=False) 
            elif not os.path.isdir(cgroup_path()):
                logger.error("Could not mount cgroups: ordinary file at {0}", path)
                return

            controllers_to_mount = ['cpu,cpuacct', 'memory']
            errors = 0
            cpu_mounted = False
            for controller in controllers_to_mount:
                try:
                    target_path = cgroup_path(controller)
                    if not os.path.exists(target_path):
                        fileutil.mkdir(target_path)
                        osutil.mount(device=controller,
                                   mount_point=target_path, 
                                   option="-t cgroup -o {0}".format(controller), 
                                   chk_err=False) 
                        if controller == 'cpu,cpuacct':
                            cpu_mounted = True
                except Exception as exception:
                    errors += 1
                    if errors == len(controllers_to_mount):
                        raise
                    logger.warn("Could not mount cgroup controller {0}: {1}", controller, ustr(exception))

            if cpu_mounted:
                for controller in ['cpu', 'cpuacct']:
                    target_path = cgroup_path(controller)
                    if not os.path.exists(target_path):
                        os.symlink(cgroup_path('cpu,cpuacct'), target_path)

        except OSError as oe: # pylint: disable=C0103
            # log a warning for read-only file systems
            logger.warn("Could not mount cgroups: {0}", ustr(oe))
            raise
        except Exception as e: # pylint: disable=C0103
            logger.error("Could not mount cgroups: {0}", ustr(e))
            raise

    def cleanup_legacy_cgroups(self):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. This
        method moves the daemon's PID from the legacy cgroups to the newer cgroups.
        """
        def move_daemon_pid(controller, daemon_pid):
            new_path = FileSystemCgroupsApi._get_agent_cgroup_path(controller)
            logger.info("Writing daemon's PID ({0}) to {1}", daemon_pid, new_path)
            fileutil.append_file(os.path.join(new_path, "cgroup.procs"), daemon_pid)
            msg = "Moved daemon's PID from legacy cgroup to {0}".format(new_path)
            add_event(op=WALAEventOperation.CGroupsCleanUp, is_success=True, message=msg)

        return CGroupsApi._foreach_legacy_cgroup(move_daemon_pid)

    def create_agent_cgroups(self):
        """
        Creates a cgroup for the VM Agent in each of the controllers we are tracking; returns the created cgroups.
        """
        cgroups = []

        pid = int(os.getpid())

        def create_cgroup(controller):
            path = FileSystemCgroupsApi._get_agent_cgroup_path(controller)

            if not os.path.isdir(path):
                FileSystemCgroupsApi._try_mkdir(path)
                logger.info("Created cgroup {0}".format(path))

            self._add_process_to_cgroup(pid, path)

            cgroups.append(CGroup.create(path, controller, VM_AGENT_CGROUP_NAME))

        self._foreach_controller(create_cgroup, 'Failed to create a cgroup for the VM Agent; resource usage will not be tracked')

        if len(cgroups) == 0: # pylint: disable=len-as-condition
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

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, # pylint: disable=R0913
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        """
        Starts a command (install/enable/etc) for an extension and adds the command's PID to the extension's cgroup
        :param extension_name: The extension executing the command
        :param command: The command to invoke
        :param timeout: Number of seconds to wait for command completion
        :param cwd: The working directory for the command
        :param env: The environment to pass to the command's process
        :param stdout: File object to redirect stdout to
        :param stderr: File object to redirect stderr to
        :param error_code: Extension error code to raise in case of error
        """
        # pylint: disable=too-many-locals
        try:
            extension_cgroups = self.create_extension_cgroups(extension_name)
        except Exception as exception:
            extension_cgroups = []
            logger.warn("Failed to create cgroups for extension '{0}'; resource usage will not be tracked. "
                        "Error: {1}".format(extension_name, ustr(exception)))

        def pre_exec_function():
            os.setsid()

            try:
                pid = os.getpid()

                for cgroup in extension_cgroups:
                    try:
                        self._add_process_to_cgroup(pid, cgroup.path)
                    except Exception as exception:
                        logger.warn("Failed to add PID {0} to the cgroups for extension '{1}'. "
                                    "Resource usage will not be tracked. Error: {2}".format(pid,
                                                                                            extension_name,
                                                                                            ustr(exception)))
            except Exception as e: # pylint: disable=C0103
                logger.warn("Failed to add extension {0} to its cgroup. Resource usage will not be tracked. "
                            "Error: {1}".format(extension_name, ustr(e)))

        process = subprocess.Popen(command, # pylint: disable=W1509
                                   shell=shell,
                                   cwd=cwd,
                                   env=env,
                                   stdout=stdout,
                                   stderr=stderr,
                                   preexec_fn=pre_exec_function)

        self.track_cgroups(extension_cgroups)
        process_output = handle_process_completion(process=process,
                                                   command=command,
                                                   timeout=timeout,
                                                   stdout=stdout,
                                                   stderr=stderr,
                                                   error_code=error_code)

        return extension_cgroups, process_output


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """
    def __init__(self):
        self._cgroup_mountpoints = None
        self._agent_unit_name = None

    @staticmethod
    def get_systemd_version():
        # the output is similar to
        #    $ systemctl --version
        #    systemd 245 (245.4-4ubuntu3)
        #    +PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP etc
        #
        return shellutil.run_command(['systemctl', '--version'])

    def get_cgroup_mount_points(self):
        """
        Returns a tuple with the mount points for the cpu and memory controllers; the values can be None
        if the corresponding controller is not mounted
        """
        # the output of mount is similar to
        #     $ mount -t cgroup
        #     cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
        #     cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
        #     cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
        #     etc
        #
        if self._cgroup_mountpoints is None:
            cpu = None
            memory = None
            for line in shellutil.run_command(['mount', '-t', 'cgroup']).splitlines():
                match = re.search(r'on\s+(?P<path>/\S+(memory|cpuacct))\s', line)
                if match is not None:
                    path = match.group('path')
                    if 'cpuacct' in path:
                        cpu = path
                    else:
                        memory = path
            self._cgroup_mountpoints = {'cpu': cpu, 'memory': memory}

        return self._cgroup_mountpoints['cpu'],  self._cgroup_mountpoints['memory']

    @staticmethod
    def get_process_cgroup_relative_paths(process_id):
        """
        Returns a tuple with the path of the cpu and memory cgroups for the given process (relative to the mount point of the corresponding
        controller).
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the process is not in a cgroup for that controller (e.g. the controller is not mounted).
        """
        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    10:memory:/system.slice/walinuxagent.service
        #    3:cpu,cpuacct:/system.slice/walinuxagent.service
        #    etc
        cpu_path = None
        memory_path = None
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+:(?P<controller>(memory|.*cpuacct.*)):(?P<path>.+)', line)
            if match is not None:
                controller = match.group('controller')
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                if controller == 'memory':
                    memory_path = path
                else:
                    cpu_path = path

        return cpu_path, memory_path

    def get_process_cgroup_paths(self, process_id):
        """
        Returns a tuple with the path of the cpu and memory cgroups for the given process. The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the process is not in a cgroup for that controller (e.g. the controller is not mounted).
        """
        cpu_cgroup_relative_path, memory_cgroup_relative_path = self.get_process_cgroup_relative_paths(process_id)

        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()

        cpu_cgroup_path = os.path.join(cpu_mount_point, cpu_cgroup_relative_path) \
            if cpu_mount_point is not None and cpu_cgroup_relative_path is not None else None

        memory_cgroup_path = os.path.join(memory_mount_point, memory_cgroup_relative_path) \
            if memory_mount_point is not None and memory_cgroup_relative_path is not None else None

        return cpu_cgroup_path, memory_cgroup_path

    @staticmethod
    def get_cgroup2_controllers():
        """
        Returns a tuple with the mount point for the cgroups v2 controllers, and the currently mounted controllers;
        either value can be None if cgroups v2 or its controllers are not mounted
        """
        # the output of mount is similar to
        #     $ mount -t cgroup2
        #     cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
        #
        for line in shellutil.run_command(['mount', '-t', 'cgroup2']).splitlines():
            match = re.search(r'on\s+(?P<path>/\S+)\s', line)
            if match is not None:
                mount_point = match.group('path')
                controllers = None
                controllers_file = os.path.join(mount_point, 'cgroup.controllers')
                if os.path.exists(controllers_file):
                    controllers = fileutil.read_file(controllers_file)
                return mount_point, controllers
        return None, None

    @staticmethod
    def get_unit_property(unit_name, property_name):
        output = shellutil.run_command(["systemctl", "show", unit_name, "--property", property_name])
        match = re.match("[^=]+=(?P<value>.+)", output)
        if match is None:
            raise ValueError("Can't find property {0} of {1}", property_name, unit_name) # pylint: disable=W0715
        return match.group('value')

    @staticmethod
    def create_and_start_unit(unit_filename, unit_contents):
        try:
            unit_path = os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, unit_filename)
            fileutil.write_file(unit_path, unit_contents)
            shellutil.run_command(["systemctl", "daemon-reload"])
            shellutil.run_command(["systemctl", "start", unit_filename])
        except Exception as e: # pylint: disable=C0103
            raise CGroupsException("Failed to create and start {0}. Error: {1}".format(unit_filename, ustr(e)))

    @staticmethod
    def _get_extensions_slice_root_name():
        return "system-{0}.slice".format(EXTENSIONS_ROOT_CGROUP_NAME)

    def _get_extension_slice_name(self, extension_name):
        return "system-{0}-{1}.slice".format(EXTENSIONS_ROOT_CGROUP_NAME, self._get_extension_cgroup_name(extension_name))

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
        # TODO: The slice created by this function is not used currently. We need to create the extension scopes within # pylint: disable=W0511
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
            shellutil.run_command(["systemctl", "stop", unit_filename])
            fileutil.rm_files(unit_path)
            shellutil.run_command(["systemctl", "daemon-reload"])
        except Exception as e: # pylint: disable=C0103
            raise CGroupsException("Failed to remove {0}. Error: {1}".format(unit_filename, ustr(e)))

    def get_extension_cgroups(self, extension_name):
        # TODO: The slice returned by this function is not used currently. We need to create the extension scopes within # pylint: disable=W0511
        #  this slice and use the slice to monitor the cgroups. Also see comment in create_extension_cgroups.
        slice_name = self._get_extension_cgroup_name(extension_name)

        cgroups = []

        def create_cgroup(controller):
            cpu_cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, 'system.slice', slice_name)
            cgroups.append(CGroup.create(cpu_cgroup_path, controller, extension_name))

        self._foreach_controller(create_cgroup, 'Cannot retrieve cgroup for extension {0}; resource usage will not be tracked.'.format(extension_name))

        return cgroups

    def get_agent_unit_name(self):
        if self._agent_unit_name is None:
            self._agent_unit_name = get_osutil().get_service_name() + ".service"
        return self._agent_unit_name

    @staticmethod
    def get_processes_in_cgroup(cgroup_path):
        """
        Returns an array of tuples with the PID and command line of the processes that are currently
        within the cgroup for the given path (which must be within the cgroup filesystem).
        """
        #
        # The output of the command is similar to
        #
        #     Directory /sys/fs/cgroup/cpu/system.slice/walinuxagent.service:
        #     ├─27519 /usr/bin/python3 -u /usr/sbin/waagent -daemon
        #     └─27547 python3 -u bin/WALinuxAgent-2.2.48.1-py2.7.egg -run-exthandlers
        #
        output = shellutil.run_command(['systemd-cgls', cgroup_path])

        processes = []

        for line in output.splitlines():
            match = re.match('[^\d]*(?P<pid>\d+)\s+(?P<command>.+)', line) # pylint: disable=W1401
            if match is not None:
                processes.append((match.group('pid'), match.group('command')))

        return processes

    @staticmethod
    def _is_systemd_failure(scope_name, stderr):
        stderr.seek(0)
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in stderr or scope_name not in stderr

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, # pylint: disable=R0913,R0914
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        scope = "{0}_{1}".format(self._get_extension_cgroup_name(extension_name), uuid.uuid4())

        process = subprocess.Popen( # pylint: disable=W1509
            "systemd-run --unit={0} --scope {1}".format(scope, command),
            shell=shell,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=os.setsid)

        scope_name = scope + '.scope'

        logger.info("Started extension in unit '{0}'", scope_name)

        try:
            # systemd-run creates the scope under the system slice by default
            cgroup_relative_path = os.path.join('system.slice', scope_name)

            cpu_cgroup_mountpoint, memory_cgroup_mountpoint = self.get_cgroup_mount_points()

            if cpu_cgroup_mountpoint is None:
                logger.info("The CPU controller is not mounted; will not track resource usage")
            else:
                cpu_cgroup_path = os.path.join(cpu_cgroup_mountpoint, cgroup_relative_path)
                CGroupsTelemetry.track_cgroup(CpuCgroup(extension_name, cpu_cgroup_path))

            if memory_cgroup_mountpoint is None:
                logger.info("The memory controller is not mounted; will not track resource usage")
            else:
                memory_cgroup_path = os.path.join(memory_cgroup_mountpoint, cgroup_relative_path)
                CGroupsTelemetry.track_cgroup(MemoryCgroup(extension_name, memory_cgroup_path))

        except IOError as e: # pylint: disable=C0103
            if e.errno == 2:  # 'No such file or directory'
                logger.info("The extension command already completed; will not track resource usage")
            logger.info("Failed to start tracking resource usage for the extension: {0}", ustr(e))
        except Exception as e: # pylint: disable=C0103
            logger.info("Failed to start tracking resource usage for the extension: {0}", ustr(e))

        # Wait for process completion or timeout
        try:
            process_output = handle_process_completion(process=process,
                                                       command=command,
                                                       timeout=timeout,
                                                       stdout=stdout,
                                                       stderr=stderr,
                                                       error_code=error_code)
        except ExtensionError as e: # pylint: disable=C0103
            # The extension didn't terminate successfully. Determine whether it was due to systemd errors or
            # extension errors.
            systemd_failure = self._is_systemd_failure(scope, stderr)
            process_output = read_output(stdout, stderr)

            if not systemd_failure: # pylint: disable=R1720
                # There was an extension error; it either timed out or returned a non-zero exit code. Re-raise the error
                raise
            else:
                # There was an issue with systemd-run. We need to log it and retry the extension without systemd.
                if isinstance(e, ExtensionOperationError):
                    err_msg = 'Systemd process exited with code %s and output %s' % (e.exit_code, process_output) # pylint: disable=no-member
                else:
                    err_msg = "Systemd timed-out, output: %s" % process_output
                    
                event_msg = 'Failed to run systemd-run for unit {0}.scope. ' \
                            'Will retry invoking the extension without systemd. ' \
                            'Systemd-run error: {1}'.format(scope, err_msg)
                add_event(op=WALAEventOperation.InvokeCommandUsingSystemd, is_success=False, log_event=False, message=event_msg)
                logger.warn(event_msg)

                # Reset the stdout and stderr
                stdout.truncate(0)
                stderr.truncate(0)

                # Try invoking the process again, this time without systemd-run
                logger.info('Extension invocation using systemd failed, falling back to regular invocation '
                            'without cgroups tracking.')
                process = subprocess.Popen(command, # pylint: disable=W1509
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

                return process_output

        # The process terminated in time and successfully
        return process_output

    def cleanup_legacy_cgroups(self):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. If
        we find that any of the legacy groups include the PID of the daemon then we need to disable data collection for this
        instance (under systemd, moving PIDs across the cgroup file system can produce unpredictable results)
        """
        return CGroupsApi._foreach_legacy_cgroup(lambda *_: None)
