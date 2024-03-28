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
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.ga.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.exception import CGroupsException, ExtensionErrorCodes, ExtensionError, \
    ExtensionOperationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.ga.extensionprocessutil import handle_process_completion, read_output, \
    TELEMETRY_MESSAGE_MAX_LEN
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_distro

CGROUP_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
EXTENSION_SLICE_PREFIX = "azure-vmextensions"


def log_cgroup_info(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGI] " + formatted_string)
    if send_event:
        add_event(op=op, message=formatted_string)


def log_cgroup_warning(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGW] " + formatted_string)  # log as INFO for now, in the future it should be logged as WARNING
    if send_event:
        add_event(op=op, message=formatted_string, is_success=False, log_event=False)


class CGroupUtil(object):
    """
    Cgroup utility methods which are independent of systemd cgroup api.
    """
    @staticmethod
    def cgroups_supported():
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            return False
        return (distro_name.lower() == 'ubuntu' and distro_version.major >= 16) or \
               (distro_name.lower() in ('centos', 'redhat') and 8 <= distro_version.major < 9)

    @staticmethod
    def get_extension_slice_name(extension_name, old_slice=False):
        # The old slice makes it difficult for user to override the limits because they need to place drop-in files on every upgrade if extension slice is different for each version.
        # old slice includes <HandlerName>.<ExtensionName>-<HandlerVersion>
        # new slice without version <HandlerName>.<ExtensionName>
        if not old_slice:
            extension_name = extension_name.rsplit("-", 1)[0]
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return EXTENSION_SLICE_PREFIX + "-" + extension_name.replace('-', '_') + ".slice"

    @staticmethod
    def get_daemon_pid():
        return int(fileutil.read_file(get_agent_pid_file_path()).strip())

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
            cgroup = os.path.join(CGROUP_FILE_SYSTEM_ROOT, controller, "WALinuxAgent", "WALinuxAgent")
            if os.path.exists(cgroup):
                log_cgroup_info('Found legacy cgroup {0}'.format(cgroup), send_event=False)
                legacy_cgroups.append((controller, cgroup))

        try:
            for controller, cgroup in legacy_cgroups:
                procs_file = os.path.join(cgroup, "cgroup.procs")

                if os.path.exists(procs_file):
                    procs_file_contents = fileutil.read_file(procs_file).strip()
                    daemon_pid = CGroupUtil.get_daemon_pid()

                    if ustr(daemon_pid) in procs_file_contents:
                        operation(controller, daemon_pid)
        finally:
            for _, cgroup in legacy_cgroups:
                log_cgroup_info('Removing {0}'.format(cgroup), send_event=False)
                shutil.rmtree(cgroup, ignore_errors=True)
        return len(legacy_cgroups)

    @staticmethod
    def cleanup_legacy_cgroups():
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. If
        we find that any of the legacy groups include the PID of the daemon then we need to disable data collection for this
        instance (under systemd, moving PIDs across the cgroup file system can produce unpredictable results)
        """
        return CGroupUtil._foreach_legacy_cgroup(lambda *_: None)


class SystemdRunError(CGroupsException):
    """
    Raised when systemd-run fails
    """

    def __init__(self, msg=None):
        super(SystemdRunError, self).__init__(msg)


def get_cgroup_api():
    """
    Determines which version of Cgroup should be used for resource enforcement and monitoring by the Agent and returns
    the corresponding Api.

    Uses 'stat -f --format=%T /sys/fs/cgroups' to get the cgroup hierarchy in use.
        If the result is 'cgroup2fs', cgroup v2 is being used.
        If the result is 'tmpfs', cgroup v1 or a hybrid mode is being used.
            If the result of 'stat -f --format=%T /sys/fs/cgroup/unified' is 'cgroup2fs', then hybrid mode is being used.

    Raises exception if an unknown mode is detected. Also raises exception if hybrid mode is detected and there are
    controllers available to be enabled in the unified hierarchy (the agent does not support cgroups if there are
    controllers simultaneously attached to v1 and v2 hierarchies).
    """
    root_hierarchy_mode = shellutil.run_command(["stat", "-f", "--format=%T", CGROUP_FILE_SYSTEM_ROOT]).rstrip()

    if root_hierarchy_mode == "cgroup2fs":
        log_cgroup_info("Using cgroup v2 for resource enforcement and monitoring")
        return SystemdCgroupApiv2()

    elif root_hierarchy_mode == "tmpfs":
        # Check if a hybrid mode is being used
        unified_hierarchy_path = os.path.join(CGROUP_FILE_SYSTEM_ROOT, "unified")
        if os.path.exists(unified_hierarchy_path) and shellutil.run_command(["stat", "-f", "--format=%T", unified_hierarchy_path]).rstrip() == "cgroup2fs":
            # Hybrid mode is being used. Check if any controllers are available to be enabled in the unified hierarchy.
            available_unified_controllers_file = os.path.join(unified_hierarchy_path, "cgroup.controllers")
            if os.path.exists(available_unified_controllers_file):
                available_unified_controllers = fileutil.read_file(available_unified_controllers_file).rstrip()
                if available_unified_controllers != "":
                    raise CGroupsException("Detected hybrid cgroup mode, but there are controllers available to be enabled in unified hierarchy: {0}".format(available_unified_controllers))

        log_cgroup_info("Using cgroup v1 for resource enforcement and monitoring")
        return SystemdCgroupApiv1()

    raise CGroupsException("Detected unknown cgroup mode: {0}".format(root_hierarchy_mode))


class _SystemdCgroupApi(object):
    """
    Cgroup interface via systemd. Contains common api implementations between cgroup v1 and v2.
    """
    def __init__(self):
        self._agent_unit_name = None
        self._systemd_run_commands = []
        self._systemd_run_commands_lock = threading.RLock()

    def get_systemd_run_commands(self):
        """
        Returns a list of the systemd-run commands currently running (given as PIDs)
        """
        with self._systemd_run_commands_lock:
            return self._systemd_run_commands[:]

    def get_controller_root_paths(self):
        """
        Cgroup version specific. Returns a tuple with the root paths for the cpu and memory controllers; the values can
        be None if the corresponding controller is not mounted or enabled at the root cgroup.
        """
        raise NotImplementedError()

    def get_unit_cgroup_paths(self, unit_name):
        """
        Returns a tuple with the path of the cpu and memory cgroups for the given unit.
        The values returned can be None if the controller is not mounted or enabled.
        """
        # Ex: ControlGroup=/azure.slice/walinuxagent.service
        #     controlgroup_path[1:] = azure.slice/walinuxagent.service
        controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")
        cpu_root_path, memory_root_path = self.get_controller_root_paths()

        cpu_cgroup_path = os.path.join(cpu_root_path, controlgroup_path[1:]) \
            if cpu_root_path is not None else None

        memory_cgroup_path = os.path.join(memory_root_path, controlgroup_path[1:]) \
            if memory_root_path is not None else None

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_paths(self, process_id):
        """
        Returns a tuple with the path of the cpu and memory cgroups for the given process.
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the controller is not mounted or enabled.
        """
        cpu_cgroup_relative_path, memory_cgroup_relative_path = self.get_process_cgroup_relative_paths(process_id)

        cpu_root_path, memory_root_path = self.get_controller_root_paths()

        cpu_cgroup_path = os.path.join(cpu_root_path, cpu_cgroup_relative_path) \
            if cpu_root_path is not None and cpu_cgroup_relative_path is not None else None

        memory_cgroup_path = os.path.join(memory_root_path, memory_cgroup_relative_path) \
            if memory_root_path is not None and memory_cgroup_relative_path is not None else None

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_relative_paths(self, process_id):  # pylint: disable=W0613
        """
        Cgroup version specific. Returns a tuple with the path of the cpu and memory cgroups for the given process
        (relative to the root path of the corresponding controller).
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the controller is not mounted or enabled.
        """
        raise NotImplementedError()

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        """
        Cgroup version specific. Starts extension command.
        """
        raise NotImplementedError()

    @staticmethod
    def _is_systemd_failure(scope_name, stderr):
        stderr.seek(0)
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in stderr or scope_name not in stderr

    @staticmethod
    def get_processes_in_cgroup(cgroup_path):
        with open(os.path.join(cgroup_path, "cgroup.procs"), "r") as cgroup_procs:
            return [int(pid) for pid in cgroup_procs.read().split()]


class SystemdCgroupApiv1(_SystemdCgroupApi):
    """
    Cgroup v1 interface via systemd
    """
    def __init__(self):
        super(SystemdCgroupApiv1, self).__init__()
        self._cgroup_mountpoints = {}

    def get_controller_root_paths(self):
        # In v1, each controller is mounted at a different path. Use findmnt to get each path and return cpu and memory
        # mount points as a tuple.
        #
        # the output of findmnt is similar to
        #     $ findmnt -t cgroup --noheadings
        #     /sys/fs/cgroup/systemd          cgroup cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
        #     /sys/fs/cgroup/memory           cgroup cgroup rw,nosuid,nodev,noexec,relatime,memory
        #     /sys/fs/cgroup/cpu,cpuacct      cgroup cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
        #     etc
        #
        if len(self._cgroup_mountpoints) == 0:
            cpu = None
            memory = None
            for line in shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings']).splitlines():
                match = re.search(r'(?P<path>/\S+(memory|cpuacct))\s', line)
                if match is not None:
                    path = match.group('path')
                    if 'cpu,cpuacct' in path:
                        cpu = path
                    else:
                        memory = path
            self._cgroup_mountpoints = {'cpu': cpu, 'memory': memory}

        return self._cgroup_mountpoints['cpu'], self._cgroup_mountpoints['memory']

    def get_process_cgroup_relative_paths(self, process_id):
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

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        scope = "{0}_{1}".format(cmd_name, uuid.uuid4())
        extension_slice_name = CGroupUtil.get_extension_slice_name(extension_name)
        with self._systemd_run_commands_lock:
            process = subprocess.Popen(  # pylint: disable=W1509
                # Some distros like ubuntu20 by default cpu and memory accounting enabled. Thus create nested cgroups under the extension slice
                # So disabling CPU and Memory accounting prevents from creating nested cgroups, so that all the counters will be present in extension Cgroup
                # since slice unit file configured with accounting enabled.
                "systemd-run --property=CPUAccounting=no --property=MemoryAccounting=no --unit={0} --scope --slice={1} {2}".format(scope, extension_slice_name, command),
                shell=shell,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                env=env,
                preexec_fn=os.setsid)

            # We start systemd-run with shell == True so process.pid is the shell's pid, not the pid for systemd-run
            self._systemd_run_commands.append(process.pid)

        scope_name = scope + '.scope'

        log_cgroup_info("Started extension in unit '{0}'".format(scope_name), send_event=False)

        cpu_cgroup = None
        try:
            cgroup_relative_path = os.path.join('azure.slice/azure-vmextensions.slice', extension_slice_name)

            cpu_cgroup_mountpoint, memory_cgroup_mountpoint = self.get_controller_root_paths()

            if cpu_cgroup_mountpoint is None:
                log_cgroup_info("The CPU controller is not mounted; will not track resource usage", send_event=False)
            else:
                cpu_cgroup_path = os.path.join(cpu_cgroup_mountpoint, cgroup_relative_path)
                cpu_cgroup = CpuCgroup(extension_name, cpu_cgroup_path)
                CGroupsTelemetry.track_cgroup(cpu_cgroup)

            if memory_cgroup_mountpoint is None:
                log_cgroup_info("The Memory controller is not mounted; will not track resource usage", send_event=False)
            else:
                memory_cgroup_path = os.path.join(memory_cgroup_mountpoint, cgroup_relative_path)
                memory_cgroup = MemoryCgroup(extension_name, memory_cgroup_path)
                CGroupsTelemetry.track_cgroup(memory_cgroup)

        except IOError as e:
            if e.errno == 2:  # 'No such file or directory'
                log_cgroup_info("The extension command already completed; will not track resource usage", send_event=False)
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)
        except Exception as e:
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)

        # Wait for process completion or timeout
        try:
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout,
                                             stderr=stderr, error_code=error_code, cpu_cgroup=cpu_cgroup)
        except ExtensionError as e:
            # The extension didn't terminate successfully. Determine whether it was due to systemd errors or
            # extension errors.
            if not self._is_systemd_failure(scope, stderr):
                # There was an extension error; it either timed out or returned a non-zero exit code. Re-raise the error
                raise

            # There was an issue with systemd-run. We need to log it and retry the extension without systemd.
            process_output = read_output(stdout, stderr)
            # Reset the stdout and stderr
            stdout.truncate(0)
            stderr.truncate(0)

            if isinstance(e, ExtensionOperationError):
                # no-member: Instance of 'ExtensionError' has no 'exit_code' member (no-member) - Disabled: e is actually an ExtensionOperationError
                err_msg = 'Systemd process exited with code %s and output %s' % (
                    e.exit_code, process_output)  # pylint: disable=no-member
            else:
                err_msg = "Systemd timed-out, output: %s" % process_output
            raise SystemdRunError(err_msg)
        finally:
            with self._systemd_run_commands_lock:
                self._systemd_run_commands.remove(process.pid)


class SystemdCgroupApiv2(_SystemdCgroupApi):
    """
    Cgroup v2 interface via systemd
    """
    def __init__(self):
        super(SystemdCgroupApiv2, self).__init__()
        self._root_cgroup_path = None
        self._controllers_enabled_at_root = []

    def is_controller_enabled_at_root(self, controller):
        """
        Returns True if the provided controller is enabled at the root cgroup. The cgroup.subtree_control file at the
        root shows a space separated list of the controllers which are enabled to control resource distribution from
        the root cgroup to its children. If a controller is listed here, then that controller is available to enable in
        children cgroups.

                $ cat /sys/fs/cgroup/cgroup.subtree_control
                cpuset cpu io memory hugetlb pids rdma misc
        """
        if self._root_cgroup_path is not None:
            enabled_controllers_file = os.path.join(self._root_cgroup_path, 'cgroup.subtree_control')
            if os.path.exists(enabled_controllers_file):
                enabled_controllers = fileutil.read_file(enabled_controllers_file).rstrip().split(" ")
                if controller in enabled_controllers:
                    return True

        return False

    def get_controller_root_paths(self):
        # In v2, there is a unified mount point shared by all controllers. Use findmnt to get the unified mount point,
        # and check if cpu and memory are enabled at the root. Return a tuple representing the root cgroups for cpu and
        # memory. Either should be None if the corresponding controller is not enabled at the root.
        #
        # The output of findmnt is similar to
        #     $ findmnt -t cgroup2 --noheadings
        #     /sys/fs/cgroup cgroup2 cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot
        #
        # This check is necessary because all non-root "cgroup.subtree_control" files can only contain controllers
        # which are enabled in the parent's "cgroup.subtree_control" file.

        if self._root_cgroup_path is None:
            for line in shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings']).splitlines():
                match = re.search(r'(?P<path>/\S+)\s+cgroup2', line)
                if match is not None:
                    root_cgroup_path = match.group('path')
                    if root_cgroup_path is not None:
                        self._root_cgroup_path = root_cgroup_path
                        if self.is_controller_enabled_at_root('cpu'):
                            self._controllers_enabled_at_root.append('cpu')
                        if self.is_controller_enabled_at_root('memory'):
                            self._controllers_enabled_at_root.append('memory')

        root_cpu_path = self._root_cgroup_path if 'cpu' in self._controllers_enabled_at_root else None
        root_memory_path = self._root_cgroup_path if 'memory' in self._controllers_enabled_at_root else None
        return root_cpu_path, root_memory_path

    def get_process_cgroup_relative_paths(self, process_id):
        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    0::/azure.slice/walinuxagent.service
        cpu_path = None
        memory_path = None
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+::(?P<path>\S+)', line)
            if match is not None:
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                memory_path = path
                cpu_path = path

        return cpu_path, memory_path

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        raise NotImplementedError()
