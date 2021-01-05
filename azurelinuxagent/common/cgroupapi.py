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

import os
import re
import shutil
import subprocess
import threading
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup
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
AZURE_CGROUP_NAME = "azure"
EXTENSIONS_CGROUP_NAME = "vmextensions"
UNIT_FILES_FILE_SYSTEM_PATH = "/etc/systemd/system"
SYSTEMD_RUN_PATH = "/run/systemd/system/"


class CGroupsApi(object):
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
        except Exception as exception:
            logger.warn("Cannot add cgroup '{0}' to tracking list; resource usage will not be tracked. "
                        "Error: {1}".format(cgroup.path, ustr(exception)))

    @staticmethod
    def _get_extension_cgroup_name(extension_name):
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return extension_name.replace('-', '_')

    @staticmethod
    def is_systemd():
        """
        Determine if systemd is managing system services; the implementation follows the same strategy as, for example,
        sd_booted() in libsystemd, or /usr/sbin/service
        """
        return os.path.exists(SYSTEMD_RUN_PATH)

    @staticmethod
    def get_processes_in_cgroup(cgroup_path):
        with open(os.path.join(cgroup_path, "cgroup.procs"), "r") as cgroup_procs:
            return [int(pid) for pid in cgroup_procs.read().split()]

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
                    daemon_pid = CGroupsApi.get_daemon_pid()

                    if ustr(daemon_pid) in procs_file_contents:
                        operation(controller, daemon_pid)
        finally:
            for _, cgroup in legacy_cgroups:
                logger.info('Removing {0}', cgroup)
                shutil.rmtree(cgroup, ignore_errors=True)
        return len(legacy_cgroups)

    @staticmethod
    def get_daemon_pid():
        return int(fileutil.read_file(get_agent_pid_file_path()).strip())


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """
    def __init__(self):
        self._cgroup_mountpoints = None
        self._agent_unit_name = None
        self._systemd_run_commands = []
        self._systemd_run_commands_lock = threading.RLock()

    @staticmethod
    def get_systemd_version():
        # the output is similar to
        #    $ systemctl --version
        #    systemd 245 (245.4-4ubuntu3)
        #    +PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP etc
        #
        return shellutil.run_command(['systemctl', '--version'])

    @staticmethod
    def get_azure_slice():
        return os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, AZURE_CGROUP_NAME, ".slice")

    @staticmethod
    def get_extensions_slice():
        return os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, EXTENSIONS_CGROUP_NAME, ".slice")

    def get_systemd_run_commands(self):
        """
        Returns a list of the systemd-run commands currently running (given as PIDs)
        """
        with self._systemd_run_commands_lock:
            return self._systemd_run_commands[:]

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
            raise ValueError("Can't find property {0} of {1}", property_name, unit_name)  # pylint: disable=W0715
        return match.group('value')

    @staticmethod
    def create_unit_file(unit_filename, unit_contents):
        try:
            unit_path = os.path.join(UNIT_FILES_FILE_SYSTEM_PATH, unit_filename)
            fileutil.write_file(unit_path, unit_contents)
        except Exception as error:
            raise CGroupsException("Failed to create and start {0}. Error: {1}".format(unit_filename, ustr(error)))

    @staticmethod
    def _get_azure_slice_name():
        return "{0}.slice".format(AZURE_CGROUP_NAME)

    @staticmethod
    def _get_extensions_root_slice_name():
        return "{0}-{1}.slice".format(AZURE_CGROUP_NAME, EXTENSIONS_CGROUP_NAME)

    def _get_extension_slice_name(self, extension_name):
        return "{0}-{1}-{2}.slice".format(AZURE_CGROUP_NAME, EXTENSIONS_CGROUP_NAME, self._get_extension_cgroup_name(extension_name))

    def create_azure_slice(self):
        unit_contents = """[Unit]
Description=Slice for Azure VM Agent and Extensions"""
        unit_filename = self._get_azure_slice_name()
        self.create_unit_file(unit_filename, unit_contents)

        message = "Created slice for Azure VM Agent and Extensions {0}".format(unit_filename)
        add_event(op=WALAEventOperation.CGroupsInitialize, is_success=True, log_event=False, message=message)
        logger.info(message)

    def create_extensions_slice(self):
        unit_contents = """[Unit]
Description=Slice for Azure VM Extensions"""
        unit_filename = self._get_extensions_root_slice_name()

        self.create_unit_file(unit_filename, unit_contents)

        message = "Created slice for Azure VM Extensions {0}".format(unit_filename)
        add_event(op=WALAEventOperation.CGroupsInitialize, is_success=True, log_event=False, message=message)
        logger.info(message)

    def get_agent_unit_name(self):
        if self._agent_unit_name is None:
            self._agent_unit_name = get_osutil().get_service_name() + ".service"
        return self._agent_unit_name

    @staticmethod
    def _is_systemd_failure(scope_name, stderr):
        stderr.seek(0)
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in stderr or scope_name not in stderr

    def start_extension_command(self, extension_name, command, timeout, shell, cwd, env, stdout, stderr, error_code=ExtensionErrorCodes.PluginUnknownFailure): 
        scope = "{0}_{1}".format(self._get_extension_cgroup_name(extension_name), uuid.uuid4())

        with self._systemd_run_commands_lock:
            process = subprocess.Popen(  # pylint: disable=W1509
                "systemd-run --unit={0} --scope {1}".format(scope, command),
                shell=shell,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                env=env,
                preexec_fn=os.setsid)
            self._systemd_run_commands.append(process.pid)

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

        except IOError as e:
            if e.errno == 2:  # 'No such file or directory'
                logger.info("The extension command already completed; will not track resource usage")
            logger.info("Failed to start tracking resource usage for the extension: {0}", ustr(e))
        except Exception as e:
            logger.info("Failed to start tracking resource usage for the extension: {0}", ustr(e))

        # Wait for process completion or timeout
        try:
            try:
                process_output = handle_process_completion(process=process,
                                                           command=command,
                                                           timeout=timeout,
                                                           stdout=stdout,
                                                           stderr=stderr,
                                                           error_code=error_code)
            finally:
                with self._systemd_run_commands_lock:
                    self._systemd_run_commands.remove(process.pid)
        except ExtensionError as e:
            # The extension didn't terminate successfully. Determine whether it was due to systemd errors or
            # extension errors.
            systemd_failure = self._is_systemd_failure(scope, stderr)
            process_output = read_output(stdout, stderr)

            if not systemd_failure:
                # There was an extension error; it either timed out or returned a non-zero exit code. Re-raise the error
                raise
            else:
                # There was an issue with systemd-run. We need to log it and retry the extension without systemd.
                if isinstance(e, ExtensionOperationError):
                    err_msg = 'Systemd process exited with code %s and output %s' % (e.exit_code, process_output)  # pylint: disable=no-member
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
