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
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import CGroupsException, ExtensionErrorCodes, ExtensionError, \
    ExtensionOperationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion, read_output
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

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, error_code):
        raise NotImplementedError()

    def cleanup_legacy_cgroups(self):
        raise NotImplementedError()

    @staticmethod
    def track_cgroups(extension_cgroups):
        try:
            for cgroup in extension_cgroups:
                CGroupsTelemetry.track_cgroup(cgroup)
        except Exception as e:
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
        return SystemdCgroupsApi() if CGroupsApi._is_systemd() else FileSystemCgroupsApi()

    @staticmethod
    def _is_systemd():
        """
        Determine if systemd is managing system services; the implementation follows the same strategy as, for example,
        sd_booted() in libsystemd, or /usr/sbin/service
        """
        return os.path.exists('/run/systemd/system/')

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
            except Exception as e:
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
            add_event(AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.CGroupsCleanUp, is_success=True, message=msg)

        CGroupsApi._foreach_legacy_cgroup(move_daemon_pid)

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

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr,
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
            except Exception as e:
                logger.warn("Failed to add extension {0} to its cgroup. Resource usage will not be tracked. "
                            "Error: {1}".format(extension_name, ustr(e)))

        process = subprocess.Popen(command,
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

    @staticmethod
    def create_and_start_unit(unit_filename, unit_contents):
        try:
            unit_path = os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, unit_filename)
            fileutil.write_file(unit_path, unit_contents)
            shellutil.run_command(["systemctl", "daemon-reload"])
            shellutil.run_command(["systemctl", "start", unit_filename])
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
            shellutil.run_command(["systemctl", "stop", unit_filename])
            fileutil.rm_files(unit_path)
            shellutil.run_command(["systemctl", "daemon-reload"])
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

    @staticmethod
    def _is_systemd_failure(scope_name, process_output):
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in process_output or scope_name not in process_output

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        scope_name = "{0}_{1}".format(self._get_extension_cgroup_name(extension_name), uuid.uuid4())

        process = subprocess.Popen(
            "systemd-run --unit={0} --scope {1}".format(scope_name, command),
            shell=shell,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            preexec_fn=os.setsid)

        logger.info("Started extension using scope '{0}'", scope_name)
        extension_cgroups = []

        def create_cgroup(controller):
            cgroup_path = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, 'system.slice', scope_name + ".scope")
            extension_cgroups.append(CGroup.create(cgroup_path, controller, extension_name))

        self._foreach_controller(create_cgroup, 'Cannot create cgroup for extension {0}; '
                                                'resource usage will not be tracked.'.format(extension_name))
        self.track_cgroups(extension_cgroups)

        # Wait for process completion or timeout
        try:
            process_output = handle_process_completion(process=process,
                                                       command=command,
                                                       timeout=timeout,
                                                       stdout=stdout,
                                                       stderr=stderr,
                                                       error_code=error_code)
        except ExtensionError as e:
            # The extension didn't terminate successfully. Determine whether it was due to systemd errors or
            # extension errors.
            process_output = read_output(stdout, stderr)
            systemd_failure = self._is_systemd_failure(scope_name, process_output)

            if not systemd_failure:
                # There was an extension error; it either timed out or returned a non-zero exit code. Re-raise the error
                raise
            else:
                # There was an issue with systemd-run. We need to log it and retry the extension without systemd.
                err_msg = 'Systemd process exited with code %s and output %s' % (e.exit_code, process_output) \
                    if isinstance(e, ExtensionOperationError) else "Systemd timed-out, output: %s" % process_output
                event_msg = 'Failed to run systemd-run for unit {0}.scope. ' \
                            'Will retry invoking the extension without systemd. ' \
                            'Systemd-run error: {1}'.format(scope_name, err_msg)
                add_event(AGENT_NAME,
                          version=CURRENT_VERSION,
                          op=WALAEventOperation.InvokeCommandUsingSystemd,
                          is_success=False,
                          log_event=False,
                          message=event_msg)
                logger.warn(event_msg)

                # Reset the stdout and stderr
                stdout.truncate(0)
                stderr.truncate(0)

                # Try invoking the process again, this time without systemd-run
                logger.info('Extension invocation using systemd failed, falling back to regular invocation '
                            'without cgroups tracking.')
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

                return [], process_output

        # The process terminated in time and successfully
        return extension_cgroups, process_output

    def cleanup_legacy_cgroups(self):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. If
        we find that any of the legacy groups include the PID of the daemon then we disable data collection for this instance
        (under systemd, moving PIDs across the cgroup file system can produce unpredictable results)
        """
        def report_error(_, daemon_pid):
            raise CGroupsException(
                "The daemon's PID ({0}) was already added to the legacy cgroup; this invalidates resource usage data.".format(daemon_pid))

        CGroupsApi._foreach_legacy_cgroup(report_error)
