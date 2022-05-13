# -*- encoding: utf-8 -*-
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
import glob
import json
import os
import re
import subprocess
import threading

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, AGENT_NAME_TELEMETRY, MetricsCounter
from azurelinuxagent.common.cgroupapi import CGroupsApi, SystemdCgroupsApi, SystemdRunError, EXTENSION_SLICE_PREFIX
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.common.utils.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation

AZURE_SLICE = "azure.slice"
_AZURE_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM Agent and Extensions
DefaultDependencies=no
Before=slices.target
"""
_VMEXTENSIONS_SLICE = EXTENSION_SLICE_PREFIX + ".slice"
_AZURE_VMEXTENSIONS_SLICE = AZURE_SLICE + "/" + _VMEXTENSIONS_SLICE
_VMEXTENSIONS_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM Extensions
DefaultDependencies=no
Before=slices.target
[Slice]
CPUAccounting=yes
"""
_EXTENSION_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM extension {extension_name}
DefaultDependencies=no
Before=slices.target
[Slice]
CPUAccounting=yes
CPUQuota={cpu_quota}
"""
LOGCOLLECTOR_SLICE = "azure-walinuxagent-logcollector.slice"
# More info on resource limits properties in systemd here:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_management_guide/sec-modifying_control_groups
_LOGCOLLECTOR_SLICE_CONTENTS_FMT = """
[Unit]
Description=Slice for Azure VM Agent Periodic Log Collector
DefaultDependencies=no
Before=slices.target
[Slice]
CPUAccounting=yes
CPUQuota={cpu_quota}
MemoryAccounting=yes
MemoryLimit={memory_limit}
"""
_LOGCOLLECTOR_CPU_QUOTA = "5%"
_LOGCOLLECTOR_MEMORY_LIMIT = "30M"  # K for kb, M for mb

_AGENT_DROP_IN_FILE_SLICE = "10-Slice.conf"
_AGENT_DROP_IN_FILE_SLICE_CONTENTS = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
Slice=azure.slice
"""
_DROP_IN_FILE_CPU_ACCOUNTING = "11-CPUAccounting.conf"
_DROP_IN_FILE_CPU_ACCOUNTING_CONTENTS = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
CPUAccounting=yes
"""
_DROP_IN_FILE_CPU_QUOTA = "12-CPUQuota.conf"
_DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
CPUQuota={0}
"""


class DisableCgroups(object):
    ALL = "all"
    AGENT = "agent"
    EXTENSIONS = "extensions"


def _log_cgroup_info(format_string, *args):
    message = format_string.format(*args)
    logger.info("[CGI] " + message)
    add_event(op=WALAEventOperation.CGroupsInfo, message=message)


def _log_cgroup_warning(format_string, *args):
    message = format_string.format(*args)
    logger.info("[CGW] " + message)  # log as INFO for now, in the future it should be logged as WARNING
    add_event(op=WALAEventOperation.CGroupsInfo, message=message, is_success=False, log_event=False)


class CGroupConfigurator(object):
    """
    This class implements the high-level operations on CGroups (e.g. initialization, creation, etc)

    NOTE: with the exception of start_extension_command, none of the methods in this class
    raise exceptions (cgroup operations should not block extensions)
    """

    class _Impl(object):
        def __init__(self):
            self._initialized = False
            self._cgroups_supported = False
            self._agent_cgroups_enabled = False
            self._extensions_cgroups_enabled = False
            self._cgroups_api = None
            self._agent_cpu_cgroup_path = None
            self._agent_memory_cgroup_path = None
            self._check_cgroups_lock = threading.RLock() # Protect the check_cgroups which is called from Monitor thread and main loop.

        def initialize(self):
            try:
                if self._initialized:
                    return

                # check whether cgroup monitoring is supported on the current distro
                self._cgroups_supported = CGroupsApi.cgroups_supported()
                if not self._cgroups_supported:
                    logger.info("Cgroup monitoring is not supported on {0}", get_distro())
                    return

                # check that systemd is detected correctly
                self._cgroups_api = SystemdCgroupsApi()
                if not systemd.is_systemd():
                    _log_cgroup_warning("systemd was not detected on {0}", get_distro())
                    return

                _log_cgroup_info("systemd version: {0}", systemd.get_version())

                # This is temporarily disabled while we analyze telemetry. Likely it will be removed.
                # self.__collect_azure_unit_telemetry()
                # self.__collect_agent_unit_files_telemetry()

                if not self.__check_no_legacy_cgroups():
                    return

                agent_unit_name = systemd.get_agent_unit_name()
                agent_slice = systemd.get_unit_property(agent_unit_name, "Slice")
                if agent_slice not in (AZURE_SLICE, "system.slice"):
                    _log_cgroup_warning("The agent is within an unexpected slice: {0}", agent_slice)
                    return

                self.__setup_azure_slice()

                cpu_controller_root, memory_controller_root = self.__get_cgroup_controllers()
                self._agent_cpu_cgroup_path, self._agent_memory_cgroup_path = self.__get_agent_cgroups(agent_slice,
                                                                                                       cpu_controller_root,
                                                                                                       memory_controller_root)

                if self._agent_cpu_cgroup_path is not None:
                    _log_cgroup_info("Agent CPU cgroup: {0}", self._agent_cpu_cgroup_path)
                    self.enable()
                    CGroupsTelemetry.track_cgroup(CpuCgroup(AGENT_NAME_TELEMETRY, self._agent_cpu_cgroup_path))

                _log_cgroup_info('Agent cgroups enabled: {0}', self._agent_cgroups_enabled)

            except Exception as exception:
                _log_cgroup_warning("Error initializing cgroups: {0}", ustr(exception))
            finally:
                self._initialized = True

        @staticmethod
        def __collect_azure_unit_telemetry():
            azure_units = []

            try:
                units = shellutil.run_command(['systemctl', 'list-units', 'azure*', '-all'])
                for line in units.split('\n'):
                    match = re.match(r'\s?(azure[^\s]*)\s?', line, re.IGNORECASE)
                    if match is not None:
                        azure_units.append((match.group(1), line))
            except shellutil.CommandError as command_error:
                _log_cgroup_warning("Failed to list systemd units: {0}", ustr(command_error))

            for unit_name, unit_description in azure_units:
                unit_slice = "Unknown"
                try:
                    unit_slice = systemd.get_unit_property(unit_name, "Slice")
                except Exception as exception:
                    _log_cgroup_warning("Failed to query Slice for {0}: {1}", unit_name, ustr(exception))

                _log_cgroup_info("Found an Azure unit under slice {0}: {1}", unit_slice, unit_description)

            if len(azure_units) == 0:
                try:
                    cgroups = shellutil.run_command('systemd-cgls')
                    for line in cgroups.split('\n'):
                        if re.match(r'[^\x00-\xff]+azure\.slice\s*', line, re.UNICODE):
                            logger.info(ustr("Found a cgroup for azure.slice\n{0}").format(cgroups))
                            # Don't add the output of systemd-cgls to the telemetry, since currently it does not support Unicode
                            add_event(op=WALAEventOperation.CGroupsInfo, message="Found a cgroup for azure.slice")
                except shellutil.CommandError as command_error:
                    _log_cgroup_warning("Failed to list systemd units: {0}", ustr(command_error))

        @staticmethod
        def __collect_agent_unit_files_telemetry():
            agent_unit_files = []
            agent_service_name = get_osutil().get_service_name()
            try:
                fragment_path = systemd.get_unit_property(agent_service_name, "FragmentPath")
                if fragment_path != systemd.get_agent_unit_file():
                    agent_unit_files.append(fragment_path)
            except Exception as exception:
                _log_cgroup_warning("Failed to query the agent's FragmentPath: {0}", ustr(exception))

            try:
                drop_in_paths = systemd.get_unit_property(agent_service_name, "DropInPaths")
                for path in drop_in_paths.split():
                    agent_unit_files.append(path)
            except Exception as exception:
                _log_cgroup_warning("Failed to query the agent's DropInPaths: {0}", ustr(exception))

            for unit_file in agent_unit_files:
                try:
                    with open(unit_file, "r") as file_object:
                        _log_cgroup_info("Found a custom unit file for the agent: {0}\n{1}", unit_file,
                                         file_object.read())
                except Exception as exception:
                    _log_cgroup_warning("Can't read {0}: {1}", unit_file, ustr(exception))

        def __check_no_legacy_cgroups(self):
            """
            Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent. When running
            under systemd this could produce invalid resource usage data. Cgroups should not be enabled under this condition.
            """
            legacy_cgroups = self._cgroups_api.cleanup_legacy_cgroups()
            if legacy_cgroups > 0:
                _log_cgroup_warning("The daemon's PID was added to a legacy cgroup; will not monitor resource usage.")
                return False
            return True

        def __get_cgroup_controllers(self):
            #
            # check v1 controllers
            #
            cpu_controller_root, memory_controller_root = self._cgroups_api.get_cgroup_mount_points()

            if cpu_controller_root is not None:
                logger.info("The CPU cgroup controller is mounted at {0}", cpu_controller_root)
            else:
                _log_cgroup_warning("The CPU cgroup controller is not mounted")

            if memory_controller_root is not None:
                logger.info("The memory cgroup controller is mounted at {0}", memory_controller_root)
            else:
                _log_cgroup_warning("The memory cgroup controller is not mounted")

            #
            # check v2 controllers
            #
            cgroup2_mount_point, cgroup2_controllers = self._cgroups_api.get_cgroup2_controllers()
            if cgroup2_mount_point is not None:
                _log_cgroup_info("cgroups v2 mounted at {0}.  Controllers: [{1}]", cgroup2_mount_point,
                                 cgroup2_controllers)

            return cpu_controller_root, memory_controller_root

        @staticmethod
        def __setup_azure_slice():
            """
            The agent creates "azure.slice" for use by extensions and the agent. The agent runs under "azure.slice" directly and each
            extension runs under its own slice ("Microsoft.CPlat.Extension.slice" in the example below). All the slices for
            extensions are grouped under "vmextensions.slice".

            Example:  -.slice
                      ├─user.slice
                      ├─system.slice
                      └─azure.slice
                        ├─walinuxagent.service
                        │ ├─5759 /usr/bin/python3 -u /usr/sbin/waagent -daemon
                        │ └─5764 python3 -u bin/WALinuxAgent-2.2.53-py2.7.egg -run-exthandlers
                        └─azure-vmextensions.slice
                          └─Microsoft.CPlat.Extension.slice
                              └─5894 /usr/bin/python3 /var/lib/waagent/Microsoft.CPlat.Extension-1.0.0.0/enable.py

            This method ensures that the "azure" and "vmextensions" slices are created. Setup should create those slices
            under /lib/systemd/system; but if they do not exist, __ensure_azure_slices_exist will create them.

            It also creates drop-in files to set the agent's Slice and CPUAccounting if they have not been
            set up in the agent's unit file.

            Lastly, the method also cleans up unit files left over from previous versions of the agent.
            """

            # Older agents used to create this slice, but it was never used. Cleanup the file.
            CGroupConfigurator._Impl.__cleanup_unit_file("/etc/systemd/system/system-walinuxagent.extensions.slice")

            unit_file_install_path = systemd.get_unit_file_install_path()
            azure_slice = os.path.join(unit_file_install_path, AZURE_SLICE)
            vmextensions_slice = os.path.join(unit_file_install_path, _VMEXTENSIONS_SLICE)
            logcollector_slice = os.path.join(unit_file_install_path, LOGCOLLECTOR_SLICE)
            agent_unit_file = systemd.get_agent_unit_file()
            agent_drop_in_path = systemd.get_agent_drop_in_path()
            agent_drop_in_file_slice = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_SLICE)
            agent_drop_in_file_cpu_accounting = os.path.join(agent_drop_in_path, _DROP_IN_FILE_CPU_ACCOUNTING)

            files_to_create = []

            if not os.path.exists(azure_slice):
                files_to_create.append((azure_slice, _AZURE_SLICE_CONTENTS))

            if not os.path.exists(vmextensions_slice):
                files_to_create.append((vmextensions_slice, _VMEXTENSIONS_SLICE_CONTENTS))

            if not os.path.exists(logcollector_slice):
                slice_contents = _LOGCOLLECTOR_SLICE_CONTENTS_FMT.format(cpu_quota=_LOGCOLLECTOR_CPU_QUOTA,
                                                                         memory_limit=_LOGCOLLECTOR_MEMORY_LIMIT)

                files_to_create.append((logcollector_slice, slice_contents))

            if fileutil.findre_in_file(agent_unit_file, r"Slice=") is not None:
                CGroupConfigurator._Impl.__cleanup_unit_file(agent_drop_in_file_slice)
            else:
                if not os.path.exists(agent_drop_in_file_slice):
                    files_to_create.append((agent_drop_in_file_slice, _AGENT_DROP_IN_FILE_SLICE_CONTENTS))

            if fileutil.findre_in_file(agent_unit_file, r"CPUAccounting=") is not None:
                CGroupConfigurator._Impl.__cleanup_unit_file(agent_drop_in_file_cpu_accounting)
            else:
                if not os.path.exists(agent_drop_in_file_cpu_accounting):
                    files_to_create.append((agent_drop_in_file_cpu_accounting, _DROP_IN_FILE_CPU_ACCOUNTING_CONTENTS))

            if len(files_to_create) > 0:
                # create the unit files, but if 1 fails remove all and return
                try:
                    for path, contents in files_to_create:
                        CGroupConfigurator._Impl.__create_unit_file(path, contents)
                except Exception as exception:
                    _log_cgroup_warning("Failed to create unit files for the azure slice: {0}", ustr(exception))
                    for unit_file in files_to_create:
                        CGroupConfigurator._Impl.__cleanup_unit_file(unit_file)
                    return

                CGroupConfigurator._Impl.__reload_systemd_config()

        @staticmethod
        def __reload_systemd_config():
            # reload the systemd configuration; the new slices will be used once the agent's service restarts
            try:
                logger.info("Executing systemctl daemon-reload...")
                shellutil.run_command(["systemctl", "daemon-reload"])
            except Exception as exception:
                _log_cgroup_warning("daemon-reload failed (create azure slice): {0}", ustr(exception))

        @staticmethod
        def __create_unit_file(path, contents):
            parent, _ = os.path.split(path)
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o755)
            exists = os.path.exists(path)
            fileutil.write_file(path, contents)
            _log_cgroup_info("{0} {1}", "Updated" if exists else "Created", path)

        @staticmethod
        def __cleanup_unit_file(path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                    _log_cgroup_info("Removed {0}", path)
                except Exception as exception:
                    _log_cgroup_warning("Failed to remove {0}: {1}", path, ustr(exception))

        @staticmethod
        def __cleanup_all_files(files_to_cleanup):
            for path in files_to_cleanup:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        _log_cgroup_info("Removed {0}", path)
                    except Exception as exception:
                        _log_cgroup_warning("Failed to remove {0}: {1}", path, ustr(exception))

        @staticmethod
        def __create_all_files(files_to_create):
            # create the unit files, but if 1 fails remove all and return
            try:
                for path, contents in files_to_create:
                    CGroupConfigurator._Impl.__create_unit_file(path, contents)
            except Exception as exception:
                _log_cgroup_warning("Failed to create unit files : {0}", ustr(exception))
                for unit_file in files_to_create:
                    CGroupConfigurator._Impl.__cleanup_unit_file(unit_file)
                return

        def is_extension_resource_limits_setup_completed(self, extension_name):
            unit_file_install_path = systemd.get_unit_file_install_path()
            extension_slice_path = os.path.join(unit_file_install_path,
                                                SystemdCgroupsApi.get_extension_slice_name(extension_name))
            if os.path.exists(extension_slice_path):
                return True
            return False

        def __get_agent_cgroups(self, agent_slice, cpu_controller_root, memory_controller_root):
            agent_unit_name = systemd.get_agent_unit_name()

            expected_relative_path = os.path.join(agent_slice, agent_unit_name)
            cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_process_cgroup_relative_paths(
                "self")

            if cpu_cgroup_relative_path is None:
                _log_cgroup_warning("The agent's process is not within a CPU cgroup")
            else:
                if cpu_cgroup_relative_path == expected_relative_path:
                    _log_cgroup_info('CPUAccounting: {0}', systemd.get_unit_property(agent_unit_name, "CPUAccounting"))
                    _log_cgroup_info('CPUQuota: {0}', systemd.get_unit_property(agent_unit_name, "CPUQuotaPerSecUSec"))
                else:
                    _log_cgroup_warning(
                        "The Agent is not in the expected CPU cgroup; will not enable monitoring. Cgroup:[{0}] Expected:[{1}]",
                        cpu_cgroup_relative_path,
                        expected_relative_path)
                    cpu_cgroup_relative_path = None  # Set the path to None to prevent monitoring

            if memory_cgroup_relative_path is None:
                _log_cgroup_warning("The agent's process is not within a memory cgroup")
            else:
                if memory_cgroup_relative_path == expected_relative_path:
                    memory_accounting = systemd.get_unit_property(agent_unit_name, "MemoryAccounting")
                    _log_cgroup_info('MemoryAccounting: {0}', memory_accounting)
                else:
                    _log_cgroup_info(
                        "The Agent is not in the expected memory cgroup; will not enable monitoring. CGroup:[{0}] Expected:[{1}]",
                        memory_cgroup_relative_path,
                        expected_relative_path)
                    memory_cgroup_relative_path = None  # Set the path to None to prevent monitoring

            if cpu_controller_root is not None and cpu_cgroup_relative_path is not None:
                agent_cpu_cgroup_path = os.path.join(cpu_controller_root, cpu_cgroup_relative_path)
            else:
                agent_cpu_cgroup_path = None

            if memory_controller_root is not None and memory_cgroup_relative_path is not None:
                agent_memory_cgroup_path = os.path.join(memory_controller_root, memory_cgroup_relative_path)
            else:
                agent_memory_cgroup_path = None

            return agent_cpu_cgroup_path, agent_memory_cgroup_path

        def supported(self):
            return self._cgroups_supported

        def enabled(self):
            return self._agent_cgroups_enabled or self._extensions_cgroups_enabled

        def agent_enabled(self):
            return self._agent_cgroups_enabled

        def extensions_enabled(self):
            return self._extensions_cgroups_enabled

        def enable(self):
            if not self.supported():
                raise CGroupsException(
                    "Attempted to enable cgroups, but they are not supported on the current platform")
            self._agent_cgroups_enabled = True
            self._extensions_cgroups_enabled = True
            self.__set_cpu_quota(conf.get_agent_cpu_quota())

        def disable(self, reason, disable_cgroups):
            if disable_cgroups == DisableCgroups.ALL:  # disable all
                # Reset quotas
                self.__reset_agent_cpu_quota()
                extension_services = self.get_extension_services_list()
                for extension in extension_services:
                    logger.info("Resetting extension : {0} and it's services: {1} CPUQuota".format(extension, extension_services[extension]))
                    self.__reset_extension_cpu_quota(extension_name=extension)
                    self.__reset_extension_services_cpu_quota(extension_services[extension])
                self.__reload_systemd_config()

                CGroupsTelemetry.reset()
                self._agent_cgroups_enabled = False
                self._extensions_cgroups_enabled = False
            elif disable_cgroups == DisableCgroups.AGENT:  # disable agent
                self._agent_cgroups_enabled = False
                self.__reset_agent_cpu_quota()
                CGroupsTelemetry.stop_tracking(CpuCgroup(AGENT_NAME_TELEMETRY, self._agent_cpu_cgroup_path))

            message = "[CGW] Disabling resource usage monitoring. Reason: {0}".format(reason)
            logger.info(message)  # log as INFO for now, in the future it should be logged as WARNING
            add_event(op=WALAEventOperation.CGroupsDisabled, message=message, is_success=False, log_event=False)

        @staticmethod
        def __set_cpu_quota(quota):
            """
            Sets the agent's CPU quota to the given percentage (100% == 1 CPU)

            NOTE: This is done using a dropin file in the default dropin directory; any local overrides on the VM will take precedence
            over this setting.
            """
            quota_percentage = "{0}%".format(quota)
            _log_cgroup_info("Ensuring the agent's CPUQuota is {0}", quota_percentage)
            if CGroupConfigurator._Impl.__try_set_cpu_quota(quota_percentage):
                CGroupsTelemetry.set_track_throttled_time(True)

        @staticmethod
        def __reset_agent_cpu_quota():
            """
            Removes any CPUQuota on the agent

            NOTE: This resets the quota on the agent's default dropin file; any local overrides on the VM will take precedence
            over this setting.
            """
            logger.info("Resetting agent's CPUQuota")
            if CGroupConfigurator._Impl.__try_set_cpu_quota(''):  # setting an empty value resets to the default (infinity)
                _log_cgroup_info('CPUQuota: {0}', systemd.get_unit_property(systemd.get_agent_unit_name(), "CPUQuotaPerSecUSec"))

        @staticmethod
        def __try_set_cpu_quota(quota):
            try:
                drop_in_file = os.path.join(systemd.get_agent_drop_in_path(), _DROP_IN_FILE_CPU_QUOTA)
                contents = _DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT.format(quota)
                if os.path.exists(drop_in_file):
                    with open(drop_in_file, "r") as file_:
                        if file_.read() == contents:
                            return True  # no need to update the file; return here to avoid doing a daemon-reload
                CGroupConfigurator._Impl.__create_unit_file(drop_in_file, contents)
            except Exception as exception:
                _log_cgroup_warning('Failed to set CPUQuota: {0}', ustr(exception))
                return False
            try:
                logger.info("Executing systemctl daemon-reload...")
                shellutil.run_command(["systemctl", "daemon-reload"])
            except Exception as exception:
                _log_cgroup_warning("daemon-reload failed (set quota): {0}", ustr(exception))
                return False
            return True

        def check_cgroups(self, cgroup_metrics):
            self._check_cgroups_lock.acquire()
            try:
                if not self.enabled():
                    return

                errors = []

                process_check_success = False
                try:
                    self._check_processes_in_agent_cgroup()
                    process_check_success = True
                except CGroupsException as exception:
                    errors.append(exception)

                quota_check_success = False
                try:
                    if cgroup_metrics:
                        self._check_agent_throttled_time(cgroup_metrics)
                    quota_check_success = True
                except CGroupsException as exception:
                    errors.append(exception)

                reason = "Check on cgroups failed:\n{0}".format("\n".join([ustr(e) for e in errors]))

                if not process_check_success and conf.get_cgroup_disable_on_process_check_failure():
                    self.disable(reason, DisableCgroups.ALL)

                if not quota_check_success and conf.get_cgroup_disable_on_quota_check_failure():
                    self.disable(reason, DisableCgroups.AGENT)
            finally:
                self._check_cgroups_lock.release()

        def _check_processes_in_agent_cgroup(self):
            """
            Verifies that the agent's cgroup includes only the current process, its parent, commands started using shellutil and instances of systemd-run
            (those processes correspond, respectively, to the extension handler, the daemon, commands started by the extension handler, and the systemd-run
            commands used to start extensions on their own cgroup).
            Other processes started by the agent (e.g. extensions) and processes not started by the agent (e.g. services installed by extensions) are reported
            as unexpected, since they should belong to their own cgroup.

            Raises a CGroupsException if the check fails
            """
            unexpected = []

            try:
                daemon = os.getppid()
                extension_handler = os.getpid()
                agent_commands = set()
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands = set()
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())
                agent_cgroup = CGroupsApi.get_processes_in_cgroup(self._agent_cpu_cgroup_path)
                # get the running commands again in case new commands started or completed while we were fetching the processes in the cgroup;
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())

                for process in agent_cgroup:
                    # Note that the agent uses systemd-run to start extensions; systemd-run belongs to the agent cgroup, though the extensions don't.
                    if process in (daemon, extension_handler) or process in systemd_run_commands:
                        continue
                    # systemd_run_commands contains the shell that started systemd-run, so we also need to check for the parent
                    if self._get_parent(process) in systemd_run_commands and self._get_command(
                            process) == 'systemd-run':
                        continue
                    # check if the process is a command started by the agent or a descendant of one of those commands
                    current = process
                    while current != 0 and current not in agent_commands:
                        current = self._get_parent(current)
                    # Process started by agent will have a marker and check if that marker found in process environment.
                    if current == 0 and not self.__is_process_descendant_of_the_agent(process):
                        unexpected.append(self.__format_process(process))
                        if len(unexpected) >= 5:  # collect just a small sample
                            break
            except Exception as exception:
                _log_cgroup_warning("Error checking the processes in the agent's cgroup: {0}".format(ustr(exception)))

            if len(unexpected) > 0:
                raise CGroupsException("The agent's cgroup includes unexpected processes: {0}".format(unexpected))

        @staticmethod
        def _get_command(pid):
            try:
                with open('/proc/{0}/comm'.format(pid), "r") as file_:
                    comm = file_.read()
                    if comm and comm[-1] == '\x00':  # if null-terminated, remove the null
                        comm = comm[:-1]
                    return comm.rstrip()
            except Exception:
                return "UNKNOWN"

        @staticmethod
        def __format_process(pid):
            """
            Formats the given PID as a string containing the PID and the corresponding command line truncated to 64 chars
            """
            try:
                cmdline = '/proc/{0}/cmdline'.format(pid)
                if os.path.exists(cmdline):
                    with open(cmdline, "r") as cmdline_file:
                        return "[PID: {0}] {1:64.64}".format(pid, cmdline_file.read())
            except Exception:
                pass
            return "[PID: {0}] UNKNOWN".format(pid)

        @staticmethod
        def __is_process_descendant_of_the_agent(pid):
            """
            Returns True if the process is descendant of the agent by looking at the env flag(AZURE_GUEST_AGENT_PARENT_PROCESS_NAME)
            that we set when the process starts otherwise False.
            """
            try:
                env = '/proc/{0}/environ'.format(pid)
                if os.path.exists(env):
                    with open(env, "r") as env_file:
                        environ = env_file.read()
                        if environ and environ[-1] == '\x00':
                            environ = environ[:-1]
                        return "{0}={1}".format(shellutil.PARENT_PROCESS_NAME, shellutil.AZURE_GUEST_AGENT) in environ
            except Exception:
                pass
            return False

        @staticmethod
        def _check_agent_throttled_time(cgroup_metrics):
            for metric in cgroup_metrics:
                if metric.instance == AGENT_NAME_TELEMETRY and metric.counter == MetricsCounter.THROTTLED_TIME:
                    if metric.value > conf.get_agent_cpu_throttled_time_threshold():
                        raise CGroupsException("The agent has been throttled for {0} seconds".format(metric.value))

        @staticmethod
        def _get_parent(pid):
            """
            Returns the parent of the given process. If the parent cannot be determined returns 0 (which is the PID for the scheduler)
            """
            try:
                stat = '/proc/{0}/stat'.format(pid)
                if os.path.exists(stat):
                    with open(stat, "r") as stat_file:
                        return int(stat_file.read().split()[3])
            except Exception:
                pass
            return 0

        def start_tracking_unit_cgroups(self, unit_name):
            """
            TODO: Start tracking Memory Cgroups
            """
            try:
                cpu_cgroup_path, _ = self._cgroups_api.get_unit_cgroup_paths(unit_name)

                if cpu_cgroup_path is None:
                    logger.info("The CPU controller is not mounted; will not track resource usage")
                else:
                    CGroupsTelemetry.track_cgroup(CpuCgroup(unit_name, cpu_cgroup_path))

            except Exception as exception:
                logger.info("Failed to start tracking resource usage for the extension: {0}", ustr(exception))

        def stop_tracking_unit_cgroups(self, unit_name):
            """
            TODO: remove Memory cgroups from tracked list.
            """
            try:
                cpu_cgroup_path, _ = self._cgroups_api.get_unit_cgroup_paths(unit_name)

                if cpu_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(CpuCgroup(unit_name, cpu_cgroup_path))

            except Exception as exception:
                logger.info("Failed to stop tracking resource usage for the extension service: {0}", ustr(exception))

        def stop_tracking_extension_cgroups(self, extension_name):
            """
            TODO: remove extension Memory cgroups from tracked list
            """
            try:
                extension_slice_name = SystemdCgroupsApi.get_extension_slice_name(extension_name)
                cgroup_relative_path = os.path.join(_AZURE_VMEXTENSIONS_SLICE,
                                                    extension_slice_name)

                cpu_cgroup_mountpoint, _ = self._cgroups_api.get_cgroup_mount_points()
                cpu_cgroup_path = os.path.join(cpu_cgroup_mountpoint, cgroup_relative_path)

                if cpu_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(CpuCgroup(extension_name, cpu_cgroup_path))

            except Exception as exception:
                logger.info("Failed to stop tracking resource usage for the extension service: {0}", ustr(exception))

        def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                    error_code=ExtensionErrorCodes.PluginUnknownFailure):
            """
            Starts a command (install/enable/etc) for an extension and adds the command's PID to the extension's cgroup
            :param extension_name: The extension executing the command
            :param command: The command to invoke
            :param cmd_name: The type of the command(enable, install, etc.)
            :param timeout: Number of seconds to wait for command completion
            :param cwd: The working directory for the command
            :param env:  The environment to pass to the command's process
            :param stdout: File object to redirect stdout to
            :param stderr: File object to redirect stderr to
            :param stderr: File object to redirect stderr to
            :param error_code: Extension error code to raise in case of error
            """
            if self.enabled():
                try:
                    return self._cgroups_api.start_extension_command(extension_name, command, cmd_name, timeout,
                                                                     shell=shell, cwd=cwd, env=env, stdout=stdout,
                                                                     stderr=stderr, error_code=error_code)
                except SystemdRunError as exception:
                    reason = 'Failed to start {0} using systemd-run, will try invoking the extension directly. Error: {1}'.format(
                        extension_name, ustr(exception))
                    self.disable(reason, DisableCgroups.ALL)
                    # fall-through and re-invoke the extension

            # subprocess-popen-preexec-fn<W1509> Disabled: code is not multi-threaded
            process = subprocess.Popen(command, shell=shell, cwd=cwd, env=env, stdout=stdout, stderr=stderr, preexec_fn=os.setsid)  # pylint: disable=W1509
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout, stderr=stderr, error_code=error_code)

        def __reset_extension_cpu_quota(self, extension_name):
            """
            Removes any CPUQuota on the extension

            NOTE: This resets the quota on the extension's slice; any local overrides on the VM will take precedence
            over this setting.
            """
            if self.enabled():
                self.setup_extension_slice(extension_name, cpu_quota=None)

        def setup_extension_slice(self, extension_name, cpu_quota):
            """
            Each extension runs under its own slice (Ex "Microsoft.CPlat.Extension.slice"). All the slices for
            extensions are grouped under "azure-vmextensions.slice.

            This method ensures that the extension slice is created. Setup should create
            under /lib/systemd/system if it is not exist.
            TODO: set memory quotas
            """
            if self.enabled():
                unit_file_install_path = systemd.get_unit_file_install_path()
                extension_slice_path = os.path.join(unit_file_install_path,
                                                    SystemdCgroupsApi.get_extension_slice_name(extension_name))
                try:
                    cpu_quota = str(cpu_quota) + "%" if cpu_quota is not None else ""  # setting an empty value resets to the default (infinity)
                    slice_contents = _EXTENSION_SLICE_CONTENTS.format(extension_name=extension_name, cpu_quota=cpu_quota)
                    CGroupConfigurator._Impl.__create_unit_file(extension_slice_path, slice_contents)
                except Exception as exception:
                    _log_cgroup_warning("Failed to set the extension {0} slice and quotas: {1}", extension_name, ustr(exception))
                    CGroupConfigurator._Impl.__cleanup_unit_file(extension_slice_path)

        def remove_extension_slice(self, extension_name):
            """
            This method ensures that the extension slice gets removed from /lib/systemd/system if it exist
            Lastly stop the unit. This would ensure the cleanup the /sys/fs/cgroup controller paths
            """
            if self.enabled():
                unit_file_install_path = systemd.get_unit_file_install_path()
                extension_slice_name = SystemdCgroupsApi.get_extension_slice_name(extension_name)
                extension_slice_path = os.path.join(unit_file_install_path, extension_slice_name)
                if os.path.exists(extension_slice_path):
                    self.stop_tracking_extension_cgroups(extension_name)
                    CGroupConfigurator._Impl.__cleanup_unit_file(extension_slice_path)

        def set_extension_services_cpu_memory_quota(self, services_list):
            """
            Each extension service will have name, systemd path and it's quotas.
            This method ensures that drop-in files are created under service.d folder if quotas given.
            ex: /lib/systemd/system/extension.service.d/11-CPUAccounting.conf
            TODO: set memory quotas
            """
            if self.enabled() and services_list is not None:
                for service in services_list:
                    service_name = service.get('name', None)
                    unit_file_path = systemd.get_unit_file_install_path()
                    if service_name is not None and unit_file_path is not None:
                        files_to_create = []
                        drop_in_path = os.path.join(unit_file_path, "{0}.d".format(service_name))
                        drop_in_file_cpu_accounting = os.path.join(drop_in_path,
                                                                   _DROP_IN_FILE_CPU_ACCOUNTING)
                        files_to_create.append((drop_in_file_cpu_accounting, _DROP_IN_FILE_CPU_ACCOUNTING_CONTENTS))

                        cpu_quota = service.get('cpuQuotaPercentage', None)
                        if cpu_quota is not None:
                            cpu_quota = str(cpu_quota) + "%"
                            drop_in_file_cpu_quota = os.path.join(drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                            cpu_quota_contents = _DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT.format(cpu_quota)
                            files_to_create.append((drop_in_file_cpu_quota, cpu_quota_contents))

                        self.__create_all_files(files_to_create)
                        self.__reload_systemd_config()

        def __reset_extension_services_cpu_quota(self, services_list):
            """
            Removes any CPUQuota on the extension service

            NOTE: This resets the quota on the extension service's default dropin file; any local overrides on the VM will take precedence
            over this setting.
            """
            if self.enabled() and services_list is not None:
                try:
                    service_name = None
                    for service in services_list:
                        service_name = service.get('name', None)
                        unit_file_path = systemd.get_unit_file_install_path()
                        if service_name is not None and unit_file_path is not None:
                            files_to_create = []
                            drop_in_path = os.path.join(unit_file_path, "{0}.d".format(service_name))
                            cpu_quota = ""  # setting an empty value resets to the default (infinity)
                            drop_in_file_cpu_quota = os.path.join(drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                            cpu_quota_contents = _DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT.format(cpu_quota)
                            if os.path.exists(drop_in_file_cpu_quota):
                                with open(drop_in_file_cpu_quota, "r") as file_:
                                    if file_.read() == cpu_quota_contents:
                                        return
                                files_to_create.append((drop_in_file_cpu_quota, cpu_quota_contents))
                            self.__create_all_files(files_to_create)
                except Exception as exception:
                    _log_cgroup_warning('Failed to reset CPUQuota for {0} : {1}', service_name, ustr(exception))

        def remove_extension_services_drop_in_files(self, services_list):
            """
            Remove the dropin files from service .d folder for the given service
            """
            if services_list is not None:
                for service in services_list:
                    service_name = service.get('name', None)
                    unit_file_path = systemd.get_unit_file_install_path()
                    if service_name is not None and unit_file_path is not None:
                        files_to_cleanup = []
                        drop_in_path = os.path.join(unit_file_path, "{0}.d".format(service_name))
                        drop_in_file_cpu_accounting = os.path.join(drop_in_path,
                                                                   _DROP_IN_FILE_CPU_ACCOUNTING)
                        files_to_cleanup.append(drop_in_file_cpu_accounting)
                        cpu_quota = service.get('cpuQuotaPercentage', None)
                        if cpu_quota is not None:
                            drop_in_file_cpu_quota = os.path.join(drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                            files_to_cleanup.append(drop_in_file_cpu_quota)

                        CGroupConfigurator._Impl.__cleanup_all_files(files_to_cleanup)
                        _log_cgroup_info("Drop in files removed for {0}".format(service_name))

        def stop_tracking_extension_services_cgroups(self, services_list):
            """
            Remove the cgroup entry from the tracked groups to stop tracking.
            """
            if self.enabled() and services_list is not None:
                for service in services_list:
                    service_name = service.get('name', None)
                    if service_name is not None:
                        self.stop_tracking_unit_cgroups(service_name)

        def start_tracking_extension_services_cgroups(self, services_list):
            """
            Add the cgroup entry to start tracking the services cgroups.
            """
            if self.enabled() and services_list is not None:
                for service in services_list:
                    service_name = service.get('name', None)
                    if service_name is not None:
                        self.start_tracking_unit_cgroups(service_name)

        @staticmethod
        def get_extension_services_list():
            """
            ResourceLimits for extensions are coming from <extName>/HandlerManifest.json file.
            Use this pattern to determine all the installed extension HandlerManifest files and
            read the extension services if ResourceLimits are present.
            """
            extensions_services = {}
            for manifest_path in glob.iglob(os.path.join(conf.get_lib_dir(), "*/HandlerManifest.json")):
                match = re.search("(?P<extname>[\\w+\\.-]+).HandlerManifest\\.json", manifest_path)
                if match is not None:
                    extensions_name = match.group('extname')
                    if not extensions_name.startswith('WALinuxAgent'):
                        try:
                            data = json.loads(fileutil.read_file(manifest_path))
                            resource_limits = data[0].get('resourceLimits', None)
                            services = resource_limits.get('services') if resource_limits else None
                            extensions_services[extensions_name] = services
                        except (IOError, OSError) as e:
                            _log_cgroup_warning(
                                'Failed to load manifest file ({0}): {1}'.format(manifest_path, e.strerror))
                        except ValueError:
                            _log_cgroup_warning('Malformed manifest file ({0}).'.format(manifest_path))
            return extensions_services

    # unique instance for the singleton
    _instance = None

    @staticmethod
    def get_instance():
        if CGroupConfigurator._instance is None:
            CGroupConfigurator._instance = CGroupConfigurator._Impl()
        return CGroupConfigurator._instance
