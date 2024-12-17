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
import json
import os
import re
import shutil
import subprocess
import threading
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.ga.cpucontroller import _CpuController, CpuControllerV1, CpuControllerV2
from azurelinuxagent.ga.memorycontroller import MemoryControllerV1, MemoryControllerV2
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
    def distro_supported():
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


class InvalidCgroupMountpointException(CGroupsException):
    """
    Raised when the cgroup mountpoint is invalid.
    """

    def __init__(self, msg=None):
        super(InvalidCgroupMountpointException, self).__init__(msg)


def create_cgroup_api():
    """
    Determines which version of Cgroup should be used for resource enforcement and monitoring by the Agent and returns
    the corresponding Api.

    Uses 'stat -f --format=%T /sys/fs/cgroup' to get the cgroup hierarchy in use.
        If the result is 'cgroup2fs', cgroup v2 is being used.
        If the result is 'tmpfs', cgroup v1 or a hybrid mode is being used.
            If the result of 'stat -f --format=%T /sys/fs/cgroup/unified' is 'cgroup2fs', then hybrid mode is being used.

    Raises exception if cgroup filesystem mountpoint is not '/sys/fs/cgroup', or an unknown mode is detected. Also
    raises exception if hybrid mode is detected and there are controllers available to be enabled in the unified
    hierarchy (the agent does not support cgroups if there are controllers simultaneously attached to v1 and v2
    hierarchies).
    """
    if not os.path.exists(CGROUP_FILE_SYSTEM_ROOT):
        v1_mount_point = shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings'])
        v2_mount_point = shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings'])
        raise InvalidCgroupMountpointException("Expected cgroup filesystem to be mounted at '{0}', but it is not.\n v1 mount point: \n{1}\n v2 mount point: \n{2}".format(CGROUP_FILE_SYSTEM_ROOT, v1_mount_point, v2_mount_point))

    root_hierarchy_mode = shellutil.run_command(["stat", "-f", "--format=%T", CGROUP_FILE_SYSTEM_ROOT]).rstrip()

    if root_hierarchy_mode == "cgroup2fs":
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

        cgroup_api_v1 = SystemdCgroupApiv1()
        # Previously the agent supported users mounting cgroup v1 controllers in locations other than the systemd
        # default ('/sys/fs/cgroup'). The agent no longer supports this scenario. If any agent supported controller is
        # mounted in a location other than the systemd default, raise Exception.
        if not cgroup_api_v1.are_mountpoints_systemd_created():
            raise InvalidCgroupMountpointException("Expected cgroup controllers to be mounted at '{0}', but at least one is not. v1 mount points: \n{1}".format(CGROUP_FILE_SYSTEM_ROOT, json.dumps(cgroup_api_v1.get_controller_mountpoints())))
        return cgroup_api_v1

    raise CGroupsException("{0} has an unexpected file type: {1}".format(CGROUP_FILE_SYSTEM_ROOT, root_hierarchy_mode))


class _SystemdCgroupApi(object):
    """
    Cgroup interface via systemd. Contains common api implementations between cgroup v1 and v2.
    """
    def __init__(self):
        self._systemd_run_commands = []
        self._systemd_run_commands_lock = threading.RLock()

    def get_cgroup_version(self):
        """
        Returns the version of the cgroup hierarchy in use.
        """
        return NotImplementedError()

    def get_systemd_run_commands(self):
        """
        Returns a list of the systemd-run commands currently running (given as PIDs)
        """
        with self._systemd_run_commands_lock:
            return self._systemd_run_commands[:]

    def get_unit_cgroup(self, unit_name, cgroup_name):
        """
        Cgroup version specific. Returns a representation of the unit cgroup.

        :param unit_name: The unit to return the cgroup of.
        :param cgroup_name: A name to represent the cgroup. Used for logging/tracking purposes.
        """
        raise NotImplementedError()

    def get_cgroup_from_relative_path(self, relative_path, cgroup_name):
        """
        Cgroup version specific. Returns a representation of the cgroup at the provided relative path.

        :param relative_path: The relative path to return the cgroup of.
        :param cgroup_name: A name to represent the cgroup. Used for logging/tracking purposes.
        """
        raise NotImplementedError()

    def get_process_cgroup(self, process_id, cgroup_name):
        """
        Cgroup version specific. Returns a representation of the process' cgroup.

        :param process_id: A numeric PID to return the cgroup of, or the string "self" to return the cgroup of the current process.
        :param cgroup_name: A name to represent the cgroup. Used for logging/tracking purposes.
        """
        raise NotImplementedError()

    def log_root_paths(self):
        """
        Cgroup version specific. Logs the root paths of the cgroup filesystem/controllers.
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


class SystemdCgroupApiv1(_SystemdCgroupApi):
    """
    Cgroup v1 interface via systemd
    """
    def __init__(self):
        super(SystemdCgroupApiv1, self).__init__()
        self._cgroup_mountpoints = self._get_controller_mountpoints()

    @staticmethod
    def _get_controller_mountpoints():
        """
        In v1, each controller is mounted at a different path. Use findmnt to get each path.

            the output of findmnt is similar to
                $ findmnt -t cgroup --noheadings
                /sys/fs/cgroup/systemd          cgroup cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
                /sys/fs/cgroup/memory           cgroup cgroup rw,nosuid,nodev,noexec,relatime,memory
                /sys/fs/cgroup/cpu,cpuacct      cgroup cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
                etc

        Returns a dictionary of the controller-path mappings. The dictionary only includes the controllers which are
        supported by the agent.
        """
        mount_points = {}
        for line in shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings']).splitlines():
            # In v2, we match only the systemd default mountpoint ('/sys/fs/cgroup'). In v1, we match any path. This
            # is because the agent previously supported users mounting controllers at locations other than the systemd
            # default in v1.
            match = re.search(r'(?P<path>\S+\/(?P<controller>\S+))\s+cgroup', line)
            if match is not None:
                path = match.group('path')
                controller = match.group('controller')
                if controller is not None and path is not None and controller in CgroupV1.get_supported_controller_names():
                    mount_points[controller] = path
        return mount_points

    def get_cgroup_version(self):
        """
        Returns the version of the cgroup hierarchy in use.
        """
        return "v1"

    def get_controller_mountpoints(self):
        """
        Returns a dictionary of controller-mountpoint mappings.
        """
        return self._cgroup_mountpoints

    def are_mountpoints_systemd_created(self):
        """
        Systemd mounts each controller at '/sys/fs/cgroup/<controller>'. Returns True if all mounted controllers which
        are supported by the agent have mountpoints which match this pattern, False otherwise.

        The agent does not support cgroup usage if the default root systemd mountpoint (/sys/fs/cgroup) is not used.
        This method is used to check if any users are using non-systemd mountpoints. If they are, the agent drop-in
        files will be cleaned up in cgroupconfigurator.
        """
        for controller, mount_point in self._cgroup_mountpoints.items():
            if mount_point != os.path.join(CGROUP_FILE_SYSTEM_ROOT, controller):
                return False
        return True

    @staticmethod
    def _get_process_relative_controller_paths(process_id):
        """
        Returns the relative paths of the cgroup for the given process as a dict of controller-path mappings. The result
        only includes controllers which are supported.
        The contents of the /proc/{process_id}/cgroup file are similar to
            # cat /proc/1218/cgroup
            10:memory:/system.slice/walinuxagent.service
            3:cpu,cpuacct:/system.slice/walinuxagent.service
            etc

        :param process_id: A numeric PID to return the relative paths of, or the string "self" to return the relative paths of the current process.
        """
        conroller_relative_paths = {}
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+:(?P<controller>.+):(?P<path>.+)', line)
            if match is not None:
                controller = match.group('controller')
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                if path is not None and controller in CgroupV1.get_supported_controller_names():
                    conroller_relative_paths[controller] = path

        return conroller_relative_paths

    def get_unit_cgroup(self, unit_name, cgroup_name):
        unit_cgroup_relative_path = systemd.get_unit_property(unit_name, "ControlGroup")
        unit_controller_paths = {}

        for controller, mountpoint in self._cgroup_mountpoints.items():
            unit_controller_paths[controller] = os.path.join(mountpoint, unit_cgroup_relative_path[1:])

        return CgroupV1(cgroup_name=cgroup_name, controller_mountpoints=self._cgroup_mountpoints,
                        controller_paths=unit_controller_paths)

    def get_cgroup_from_relative_path(self, relative_path, cgroup_name):
        controller_paths = {}
        for controller, mountpoint in self._cgroup_mountpoints.items():
            controller_paths[controller] = os.path.join(mountpoint, relative_path)

        return CgroupV1(cgroup_name=cgroup_name, controller_mountpoints=self._cgroup_mountpoints,
                        controller_paths=controller_paths)

    def get_process_cgroup(self, process_id, cgroup_name):
        relative_controller_paths = self._get_process_relative_controller_paths(process_id)
        process_controller_paths = {}

        for controller, mountpoint in self._cgroup_mountpoints.items():
            relative_controller_path = relative_controller_paths.get(controller)
            if relative_controller_path is not None:
                process_controller_paths[controller] = os.path.join(mountpoint, relative_controller_path)

        return CgroupV1(cgroup_name=cgroup_name, controller_mountpoints=self._cgroup_mountpoints,
                        controller_paths=process_controller_paths)

    def log_root_paths(self):
        for controller in CgroupV1.get_supported_controller_names():
            mount_point = self._cgroup_mountpoints.get(controller)
            if mount_point is None:
                log_cgroup_info("The {0} controller is not mounted".format(controller))
            else:
                log_cgroup_info("The {0} controller is mounted at {1}".format(controller, mount_point))

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

        cpu_controller = None
        try:
            cgroup_relative_path = os.path.join('azure.slice/azure-vmextensions.slice', extension_slice_name)
            cgroup = self.get_cgroup_from_relative_path(cgroup_relative_path, extension_name)
            for controller in cgroup.get_controllers():
                if isinstance(controller, _CpuController):
                    cpu_controller = controller
                CGroupsTelemetry.track_cgroup_controller(controller)

        except IOError as e:
            if e.errno == 2:  # 'No such file or directory'
                log_cgroup_info("The extension command already completed; will not track resource usage", send_event=False)
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)
        except Exception as e:
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)

        # Wait for process completion or timeout
        try:
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout,
                                             stderr=stderr, error_code=error_code, cpu_controller=cpu_controller)
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
        self._root_cgroup_path = self._get_root_cgroup_path()
        self._controllers_enabled_at_root = self._get_controllers_enabled_at_root(self._root_cgroup_path) if self._root_cgroup_path != "" else []

    @staticmethod
    def _get_root_cgroup_path():
        """
        In v2, there is a unified mount point shared by all controllers. Use findmnt to get the unified mount point.

          The output of findmnt is similar to
              $ findmnt -t cgroup2 --noheadings
              /sys/fs/cgroup cgroup2 cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot

        Returns empty string if the root cgroup cannot be determined from the output above.
        """
        #
        for line in shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings']).splitlines():
            # Systemd mounts the cgroup filesystem at '/sys/fs/cgroup'. The agent does not support cgroups if the
            # filesystem is mounted elsewhere, so search specifically for '/sys/fs/cgroup' in the findmnt output.
            match = re.search(r'(?P<path>\/sys\/fs\/cgroup)\s+cgroup2', line)
            if match is not None:
                root_cgroup_path = match.group('path')
                if root_cgroup_path is not None:
                    return root_cgroup_path
        return ""

    def get_cgroup_version(self):
        """
        Returns the version of the cgroup hierarchy in use.
        """
        return "v2"

    def get_root_cgroup_path(self):
        """
        Returns the unified cgroup mountpoint.
        """
        return self._root_cgroup_path

    @staticmethod
    def _get_controllers_enabled_at_root(root_cgroup_path):
        """
        Returns a list of the controllers enabled at the root cgroup. The cgroup.subtree_control file at the root shows
        a space separated list of the controllers which are enabled to control resource distribution from the root
        cgroup to its children. If a controller is listed here, then that controller is available to enable in children
        cgroups. Returns only the enabled controllers which are supported by the agent.

                $ cat /sys/fs/cgroup/cgroup.subtree_control
                cpuset cpu io memory hugetlb pids rdma misc
        """
        enabled_controllers_file = os.path.join(root_cgroup_path, 'cgroup.subtree_control')
        if os.path.exists(enabled_controllers_file):
            controllers_enabled_at_root = fileutil.read_file(enabled_controllers_file).rstrip().split()
            return list(set(controllers_enabled_at_root) & set(CgroupV2.get_supported_controller_names()))
        return []

    @staticmethod
    def _get_process_relative_cgroup_path(process_id):
        """
        Returns the relative path of the cgroup for the given process.
        The contents of the /proc/{process_id}/cgroup file are similar to
            # cat /proc/1218/cgroup
            0::/azure.slice/walinuxagent.service

        :param process_id: A numeric PID to return the relative path of, or the string "self" to return the relative path of the current process.
        """
        relative_path = ""
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'0::(?P<path>\S+)', line)
            if match is not None:
                relative_path = match.group('path').lstrip('/') if match.group('path') != '/' else ""

        return relative_path

    def get_unit_cgroup(self, unit_name, cgroup_name):
        unit_cgroup_relative_path = systemd.get_unit_property(unit_name, "ControlGroup")
        unit_cgroup_path = ""

        if self._root_cgroup_path != "":
            unit_cgroup_path = os.path.join(self._root_cgroup_path, unit_cgroup_relative_path[1:])

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path, cgroup_path=unit_cgroup_path, enabled_controllers=self._controllers_enabled_at_root)

    def get_cgroup_from_relative_path(self, relative_path, cgroup_name):
        cgroup_path = ""
        if self._root_cgroup_path != "":
            cgroup_path = os.path.join(self._root_cgroup_path, relative_path)

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path, cgroup_path=cgroup_path, enabled_controllers=self._controllers_enabled_at_root)

    def get_process_cgroup(self, process_id, cgroup_name):
        relative_path = self._get_process_relative_cgroup_path(process_id)
        cgroup_path = ""

        if self._root_cgroup_path != "":
            cgroup_path = os.path.join(self._root_cgroup_path, relative_path)

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path, cgroup_path=cgroup_path, enabled_controllers=self._controllers_enabled_at_root)

    def log_root_paths(self):
        log_cgroup_info("The root cgroup path is {0}".format(self._root_cgroup_path))
        for controller in CgroupV2.get_supported_controller_names():
            if controller in self._controllers_enabled_at_root:
                log_cgroup_info("The {0} controller is enabled at the root cgroup".format(controller))
            else:
                log_cgroup_info("The {0} controller is not enabled at the root cgroup".format(controller))

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        raise NotImplementedError()


class Cgroup(object):
    MEMORY_CONTROLLER = "memory"

    def __init__(self, cgroup_name):
        self._cgroup_name = cgroup_name

    @staticmethod
    def get_supported_controller_names():
        """
        Cgroup version specific. Returns a list of the controllers which the agent supports as strings.
        """
        raise NotImplementedError()

    def check_in_expected_slice(self, expected_slice):
        """
        Cgroup version specific. Returns True if the cgroup is in the expected slice, False otherwise.

        :param expected_slice: The slice the cgroup is expected to be in.
        """
        raise NotImplementedError()

    def get_controllers(self, expected_relative_path=None):
        """
        Cgroup version specific. Returns a list of the agent supported controllers which are mounted/enabled for the cgroup.

        :param expected_relative_path: The expected relative path of the cgroup. If provided, only controllers mounted
        at this expected path will be returned.
        """
        raise NotImplementedError()

    def get_processes(self):
        """
        Cgroup version specific. Returns a list of all the process ids in the cgroup.
        """
        raise NotImplementedError()


class CgroupV1(Cgroup):
    CPU_CONTROLLER = "cpu,cpuacct"

    def __init__(self, cgroup_name, controller_mountpoints, controller_paths):
        """
        :param cgroup_name: The name of the cgroup. Used for logging/tracking purposes.
        :param controller_mountpoints: A dictionary of controller-mountpoint mappings for each agent supported controller which is mounted.
        :param controller_paths: A dictionary of controller-path mappings for each agent supported controller which is mounted. The path represents the absolute path of the controller.
        """
        super(CgroupV1, self).__init__(cgroup_name=cgroup_name)
        self._controller_mountpoints = controller_mountpoints
        self._controller_paths = controller_paths

    @staticmethod
    def get_supported_controller_names():
        return [CgroupV1.CPU_CONTROLLER, CgroupV1.MEMORY_CONTROLLER]

    def check_in_expected_slice(self, expected_slice):
        in_expected_slice = True
        for controller, path in self._controller_paths.items():
            if expected_slice not in path:
                log_cgroup_warning("The {0} controller for the {1} cgroup is not mounted in the expected slice. Expected slice: {2}. Actual controller path: {3}".format(controller, self._cgroup_name, expected_slice, path), send_event=False)
                in_expected_slice = False

        return in_expected_slice

    def get_controllers(self, expected_relative_path=None):
        controllers = []

        for supported_controller_name in self.get_supported_controller_names():
            controller = None
            controller_path = self._controller_paths.get(supported_controller_name)
            controller_mountpoint = self._controller_mountpoints.get(supported_controller_name)

            if controller_mountpoint is None:
                # Do not send telemetry here. We already have telemetry for unmounted controllers in cgroup init
                log_cgroup_warning("{0} controller is not mounted; will not track".format(supported_controller_name), send_event=False)
                continue

            if controller_path is None:
                log_cgroup_warning("{0} is not mounted for the {1} cgroup; will not track".format(supported_controller_name, self._cgroup_name))
                continue

            if expected_relative_path is not None:
                expected_path = os.path.join(controller_mountpoint, expected_relative_path)
                if controller_path != expected_path:
                    log_cgroup_warning("The {0} controller is not mounted at the expected path for the {1} cgroup; will not track. Actual cgroup path:[{2}] Expected:[{3}]".format(supported_controller_name, self._cgroup_name, controller_path, expected_path))
                    continue

            if supported_controller_name == self.CPU_CONTROLLER:
                controller = CpuControllerV1(self._cgroup_name, controller_path)
            elif supported_controller_name == self.MEMORY_CONTROLLER:
                controller = MemoryControllerV1(self._cgroup_name, controller_path)

            if controller is not None:
                controllers.append(controller)

        return controllers

    def get_controller_procs_path(self, controller):
        controller_path = self._controller_paths.get(controller)
        if controller_path is not None and controller_path != "":
            return os.path.join(controller_path, "cgroup.procs")
        return ""

    def get_processes(self):
        pids = set()
        for controller in self._controller_paths.keys():
            procs_path = self.get_controller_procs_path(controller)
            if os.path.exists(procs_path):
                with open(procs_path, "r") as cgroup_procs:
                    for pid in cgroup_procs.read().split():
                        pids.add(int(pid))
        return list(pids)


class CgroupV2(Cgroup):
    CPU_CONTROLLER = "cpu"

    def __init__(self, cgroup_name, root_cgroup_path, cgroup_path, enabled_controllers):
        """
        :param cgroup_name: The name of the cgroup. Used for logging/tracking purposes.
        :param root_cgroup_path: A string representing the root cgroup path. String can be empty.
        :param cgroup_path: A string representing the absolute cgroup path. String can be empty.
        :param enabled_controllers: A list of strings representing the agent supported controllers enabled at the root cgroup.
        """
        super(CgroupV2, self).__init__(cgroup_name)
        self._root_cgroup_path = root_cgroup_path
        self._cgroup_path = cgroup_path
        self._enabled_controllers = enabled_controllers

    @staticmethod
    def get_supported_controller_names():
        return [CgroupV2.CPU_CONTROLLER, CgroupV2.MEMORY_CONTROLLER]

    def check_in_expected_slice(self, expected_slice):
        if expected_slice not in self._cgroup_path:
            log_cgroup_warning("The {0} cgroup is not in the expected slice. Expected slice: {1}. Actual cgroup path: {2}".format(self._cgroup_name, expected_slice, self._cgroup_path), send_event=False)
            return False

        return True

    def get_controllers(self, expected_relative_path=None):
        controllers = []

        for supported_controller_name in self.get_supported_controller_names():
            controller = None

            if supported_controller_name not in self._enabled_controllers:
                # Do not send telemetry here. We already have telemetry for disabled controllers in cgroup init
                log_cgroup_warning("{0} controller is not enabled; will not track".format(supported_controller_name),
                                   send_event=False)
                continue

            if self._cgroup_path == "":
                log_cgroup_warning("Cgroup path for {0} cannot be determined; will not track".format(self._cgroup_name))
                continue

            if expected_relative_path is not None:
                expected_path = os.path.join(self._root_cgroup_path, expected_relative_path)
                if self._cgroup_path != expected_path:
                    log_cgroup_warning(
                        "The {0} cgroup is not mounted at the expected path; will not track. Actual cgroup path:[{1}] Expected:[{2}]".format(
                            self._cgroup_name, self._cgroup_path, expected_path))
                    continue

            if supported_controller_name == self.CPU_CONTROLLER:
                controller = CpuControllerV2(self._cgroup_name, self._cgroup_path)
            elif supported_controller_name == self.MEMORY_CONTROLLER:
                controller = MemoryControllerV2(self._cgroup_name, self._cgroup_path)

            if controller is not None:
                controllers.append(controller)

        return controllers

    def get_procs_path(self):
        if self._cgroup_path != "":
            return os.path.join(self._cgroup_path, "cgroup.procs")
        return ""

    def get_processes(self):
        pids = set()
        procs_path = self.get_procs_path()
        if os.path.exists(procs_path):
            with open(procs_path, "r") as cgroup_procs:
                for pid in cgroup_procs.read().split():
                    pids.add(int(pid))
        return list(pids)


