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
from azurelinuxagent.ga.cgroup import CpuCgroup, AGENT_NAME_TELEMETRY, MetricsCounter, MemoryCgroup
from azurelinuxagent.ga.cgroupapi import SystemdRunError, EXTENSION_SLICE_PREFIX, CGroupUtil, SystemdCgroupApiv2, \
    log_cgroup_info, log_cgroup_warning, get_cgroup_api, InvalidCgroupMountpointException
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException, AgentMemoryExceededException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.ga.extensionprocessutil import handle_process_completion
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
MemoryAccounting=yes
"""
_EXTENSION_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM extension {extension_name}
DefaultDependencies=no
Before=slices.target
[Slice]
CPUAccounting=yes
CPUQuota={cpu_quota}
MemoryAccounting=yes
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
"""
_LOGCOLLECTOR_CPU_QUOTA = "5%"
LOGCOLLECTOR_MEMORY_LIMIT = 30 * 1024 ** 2  # 30Mb

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
_DROP_IN_FILE_MEMORY_ACCOUNTING = "13-MemoryAccounting.conf"
_DROP_IN_FILE_MEMORY_ACCOUNTING_CONTENTS = """
# This drop-in unit file was created by the Azure VM Agent.
# Do not edit.
[Service]
MemoryAccounting=yes
"""


class DisableCgroups(object):
    ALL = "all"
    AGENT = "agent"
    EXTENSIONS = "extensions"


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
            self._agent_memory_cgroup = None
            self._check_cgroups_lock = threading.RLock()  # Protect the check_cgroups which is called from Monitor thread and main loop.

        def initialize(self):
            try:
                if self._initialized:
                    return
                # check whether cgroup monitoring is supported on the current distro
                self._cgroups_supported = CGroupUtil.cgroups_supported()
                if not self._cgroups_supported:
                    log_cgroup_info("Cgroup monitoring is not supported on {0}".format(get_distro()), send_event=True)
                    # If a distro is not supported, attempt to clean up any existing drop in files in case it was
                    # previously supported. It is necessary to cleanup in this scenario in case the OS hits any bugs on
                    # the kernel related to cgroups.
                    log_cgroup_info("Agent will reset the quotas in case distro: {0} went from supported to unsupported".format(get_distro()), send_event=False)
                    self._cleanup_agent_cgroup_drop_in_files()
                    return

                # check that systemd is detected correctly
                if not systemd.is_systemd():
                    log_cgroup_warning("systemd was not detected on {0}".format(get_distro()))
                    return

                log_cgroup_info("systemd version: {0}".format(systemd.get_version()))

                # Determine which version of the Cgroup Api should be used. If the correct version can't be determined,
                # do not enable resource monitoring/enforcement.
                try:
                    self._cgroups_api = get_cgroup_api()
                except InvalidCgroupMountpointException as e:
                    # Systemd mounts the cgroup file system at '/sys/fs/cgroup'. Previously, the agent supported cgroup
                    # usage if a user mounted the cgroup filesystem elsewhere. The agent no longer supports that
                    # scenario. Cleanup any existing drop in files in case the agent previously supported cgroups on
                    # this machine.
                    log_cgroup_warning("The agent does not support cgroups if the default systemd mountpoint is not being used: {0}".format(ustr(e)), send_event=True)
                    log_cgroup_info("Agent will reset the quotas in case cgroup usage went from enabled to disabled")
                    self._cleanup_agent_cgroup_drop_in_files()
                    return
                except CGroupsException as e:
                    log_cgroup_warning("Unable to determine which cgroup version to use: {0}".format(ustr(e)), send_event=True)
                    return

                if not self.__check_no_legacy_cgroups():
                    return

                agent_unit_name = systemd.get_agent_unit_name()
                agent_slice = systemd.get_unit_property(agent_unit_name, "Slice")
                if agent_slice not in (AZURE_SLICE, "system.slice"):
                    log_cgroup_warning("The agent is within an unexpected slice: {0}".format(agent_slice))
                    return

                self.__setup_azure_slice()

                if self.cgroup_v2_enabled():
                    log_cgroup_info("Agent and extensions resource monitoring is not currently supported on cgroup v2")
                    return

                cpu_controller_root, memory_controller_root = self.__get_cgroup_controller_roots()
                self._agent_cpu_cgroup_path, self._agent_memory_cgroup_path = self.__get_agent_cgroup_paths(agent_slice,
                                                                                                       cpu_controller_root,
                                                                                                       memory_controller_root)

                if self._agent_cpu_cgroup_path is not None or self._agent_memory_cgroup_path is not None:
                    self.enable()

                if self._agent_cpu_cgroup_path is not None:
                    log_cgroup_info("Agent CPU cgroup: {0}".format(self._agent_cpu_cgroup_path))
                    self.__set_cpu_quota(conf.get_agent_cpu_quota())
                    CGroupsTelemetry.track_cgroup(CpuCgroup(AGENT_NAME_TELEMETRY, self._agent_cpu_cgroup_path))

                if self._agent_memory_cgroup_path is not None:
                    log_cgroup_info("Agent Memory cgroup: {0}".format(self._agent_memory_cgroup_path))
                    self._agent_memory_cgroup = MemoryCgroup(AGENT_NAME_TELEMETRY, self._agent_memory_cgroup_path)
                    CGroupsTelemetry.track_cgroup(self._agent_memory_cgroup)

            except Exception as exception:
                log_cgroup_warning("Error initializing cgroups: {0}".format(ustr(exception)))
            finally:
                log_cgroup_info('Agent cgroups enabled: {0}'.format(self._agent_cgroups_enabled))
                self._initialized = True

        def __check_no_legacy_cgroups(self):
            """
            Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent. When running
            under systemd this could produce invalid resource usage data. Cgroups should not be enabled under this condition.
            """
            legacy_cgroups = CGroupUtil.cleanup_legacy_cgroups()
            if legacy_cgroups > 0:
                log_cgroup_warning("The daemon's PID was added to a legacy cgroup; will not monitor resource usage.")
                return False
            return True

        def __get_cgroup_controller_roots(self):
            cpu_controller_root, memory_controller_root = self._cgroups_api.get_controller_root_paths()

            if cpu_controller_root is not None:
                log_cgroup_info("The CPU cgroup controller root path is {0}".format(cpu_controller_root), send_event=False)
            else:
                log_cgroup_warning("The CPU cgroup controller is not mounted or enabled")

            if memory_controller_root is not None:
                log_cgroup_info("The memory cgroup controller root path is {0}".format(memory_controller_root), send_event=False)
            else:
                log_cgroup_warning("The memory cgroup controller is not mounted or enabled")

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
            agent_drop_in_file_memory_accounting = os.path.join(agent_drop_in_path, _DROP_IN_FILE_MEMORY_ACCOUNTING)

            files_to_create = []

            if not os.path.exists(azure_slice):
                files_to_create.append((azure_slice, _AZURE_SLICE_CONTENTS))

            if not os.path.exists(vmextensions_slice):
                files_to_create.append((vmextensions_slice, _VMEXTENSIONS_SLICE_CONTENTS))

            # Update log collector slice contents
            slice_contents = _LOGCOLLECTOR_SLICE_CONTENTS_FMT.format(cpu_quota=_LOGCOLLECTOR_CPU_QUOTA)
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

            if fileutil.findre_in_file(agent_unit_file, r"MemoryAccounting=") is not None:
                CGroupConfigurator._Impl.__cleanup_unit_file(agent_drop_in_file_memory_accounting)
            else:
                if not os.path.exists(agent_drop_in_file_memory_accounting):
                    files_to_create.append(
                        (agent_drop_in_file_memory_accounting, _DROP_IN_FILE_MEMORY_ACCOUNTING_CONTENTS))

            if len(files_to_create) > 0:
                # create the unit files, but if 1 fails remove all and return
                try:
                    for path, contents in files_to_create:
                        CGroupConfigurator._Impl.__create_unit_file(path, contents)
                except Exception as exception:
                    log_cgroup_warning("Failed to create unit files for the azure slice: {0}".format(ustr(exception)))
                    for unit_file in files_to_create:
                        CGroupConfigurator._Impl.__cleanup_unit_file(unit_file)
                    return

                CGroupConfigurator._Impl.__reload_systemd_config()

        def _cleanup_agent_cgroup_drop_in_files(self):
            try:
                agent_drop_in_path = systemd.get_agent_drop_in_path()
                if os.path.exists(agent_drop_in_path) and os.path.isdir(agent_drop_in_path):
                    files_to_cleanup = []
                    agent_drop_in_file_slice = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_SLICE)
                    agent_drop_in_file_cpu_accounting = os.path.join(agent_drop_in_path,
                                                                     _DROP_IN_FILE_CPU_ACCOUNTING)
                    agent_drop_in_file_memory_accounting = os.path.join(agent_drop_in_path,
                                                                        _DROP_IN_FILE_MEMORY_ACCOUNTING)
                    agent_drop_in_file_cpu_quota = os.path.join(agent_drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                    files_to_cleanup.extend([agent_drop_in_file_slice, agent_drop_in_file_cpu_accounting,
                                             agent_drop_in_file_memory_accounting, agent_drop_in_file_cpu_quota])
                    self.__cleanup_all_files(files_to_cleanup)
                    self.__reload_systemd_config()
            except Exception as err:
                logger.warn("Unable to delete Agent drop-in files while resetting the quotas: {0}".format(err))

        @staticmethod
        def __reload_systemd_config():
            # reload the systemd configuration; the new slices will be used once the agent's service restarts
            try:
                log_cgroup_info("Executing systemctl daemon-reload...", send_event=False)
                shellutil.run_command(["systemctl", "daemon-reload"])
            except Exception as exception:
                log_cgroup_warning("daemon-reload failed (create azure slice): {0}".format(ustr(exception)))

        # W0238: Unused private member `_Impl.__create_unit_file(path, contents)` (unused-private-member)
        @staticmethod
        def __create_unit_file(path, contents):  # pylint: disable=unused-private-member
            parent, _ = os.path.split(path)
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o755)
            exists = os.path.exists(path)
            fileutil.write_file(path, contents)
            log_cgroup_info("{0} {1}".format("Updated" if exists else "Created", path))

        # W0238: Unused private member `_Impl.__cleanup_unit_file(path)` (unused-private-member)
        @staticmethod
        def __cleanup_unit_file(path):  # pylint: disable=unused-private-member
            if os.path.exists(path):
                try:
                    os.remove(path)
                    log_cgroup_info("Removed {0}".format(path))
                except Exception as exception:
                    log_cgroup_warning("Failed to remove {0}: {1}".format(path, ustr(exception)))

        @staticmethod
        def __cleanup_all_files(files_to_cleanup):
            for path in files_to_cleanup:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        log_cgroup_info("Removed {0}".format(path))
                    except Exception as exception:
                        log_cgroup_warning("Failed to remove {0}: {1}".format(path, ustr(exception)))

        @staticmethod
        def __create_all_files(files_to_create):
            # create the unit files, but if 1 fails remove all and return
            try:
                for path, contents in files_to_create:
                    CGroupConfigurator._Impl.__create_unit_file(path, contents)
            except Exception as exception:
                log_cgroup_warning("Failed to create unit files : {0}".format(ustr(exception)))
                for unit_file in files_to_create:
                    CGroupConfigurator._Impl.__cleanup_unit_file(unit_file)
                return

        def is_extension_resource_limits_setup_completed(self, extension_name, cpu_quota=None):
            unit_file_install_path = systemd.get_unit_file_install_path()
            old_extension_slice_path = os.path.join(unit_file_install_path, CGroupUtil.get_extension_slice_name(extension_name, old_slice=True))
            # clean up the old slice from the disk
            if os.path.exists(old_extension_slice_path):
                CGroupConfigurator._Impl.__cleanup_unit_file(old_extension_slice_path)

            extension_slice_path = os.path.join(unit_file_install_path,
                                                CGroupUtil.get_extension_slice_name(extension_name))
            cpu_quota = str(
                cpu_quota) + "%" if cpu_quota is not None else ""  # setting an empty value resets to the default (infinity)
            slice_contents = _EXTENSION_SLICE_CONTENTS.format(extension_name=extension_name,
                                                              cpu_quota=cpu_quota)
            if os.path.exists(extension_slice_path):
                with open(extension_slice_path, "r") as file_:
                    if file_.read() == slice_contents:
                        return True
            return False

        def __get_agent_cgroup_paths(self, agent_slice, cpu_controller_root, memory_controller_root):
            agent_unit_name = systemd.get_agent_unit_name()

            expected_relative_path = os.path.join(agent_slice, agent_unit_name)
            cpu_cgroup_relative_path, memory_cgroup_relative_path = self._cgroups_api.get_process_cgroup_relative_paths(
                "self")

            if cpu_cgroup_relative_path is None:
                log_cgroup_warning("The agent's process is not within a CPU cgroup")
            else:
                if cpu_cgroup_relative_path == expected_relative_path:
                    log_cgroup_info('CPUAccounting: {0}'.format(systemd.get_unit_property(agent_unit_name, "CPUAccounting")))
                    log_cgroup_info('CPUQuota: {0}'.format(systemd.get_unit_property(agent_unit_name, "CPUQuotaPerSecUSec")))
                else:
                    log_cgroup_warning(
                        "The Agent is not in the expected CPU cgroup; will not enable monitoring. Cgroup:[{0}] Expected:[{1}]".format(cpu_cgroup_relative_path, expected_relative_path))
                    cpu_cgroup_relative_path = None  # Set the path to None to prevent monitoring

            if memory_cgroup_relative_path is None:
                log_cgroup_warning("The agent's process is not within a memory cgroup")
            else:
                if memory_cgroup_relative_path == expected_relative_path:
                    memory_accounting = systemd.get_unit_property(agent_unit_name, "MemoryAccounting")
                    log_cgroup_info('MemoryAccounting: {0}'.format(memory_accounting))
                else:
                    log_cgroup_warning(
                        "The Agent is not in the expected memory cgroup; will not enable monitoring. CGroup:[{0}] Expected:[{1}]".format(memory_cgroup_relative_path, expected_relative_path))
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

        def cgroup_v2_enabled(self):
            return isinstance(self._cgroups_api, SystemdCgroupApiv2)

        def enable(self):
            if not self.supported():
                raise CGroupsException(
                    "Attempted to enable cgroups, but they are not supported on the current platform")
            self._agent_cgroups_enabled = True
            self._extensions_cgroups_enabled = True

        def disable(self, reason, disable_cgroups):
            if disable_cgroups == DisableCgroups.ALL:  # disable all
                # Reset quotas
                self.__reset_agent_cpu_quota()
                extension_services = self.get_extension_services_list()
                for extension in extension_services:
                    log_cgroup_info("Resetting extension : {0} and it's services: {1} CPUQuota".format(extension, extension_services[extension]), send_event=False)
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

            log_cgroup_warning("Disabling resource usage monitoring. Reason: {0}".format(reason), op=WALAEventOperation.CGroupsDisabled)

        @staticmethod
        def __set_cpu_quota(quota):
            """
            Sets the agent's CPU quota to the given percentage (100% == 1 CPU)

            NOTE: This is done using a dropin file in the default dropin directory; any local overrides on the VM will take precedence
            over this setting.
            """
            quota_percentage = "{0}%".format(quota)
            log_cgroup_info("Ensuring the agent's CPUQuota is {0}".format(quota_percentage))
            if CGroupConfigurator._Impl.__try_set_cpu_quota(quota_percentage):
                CGroupsTelemetry.set_track_throttled_time(True)

        @staticmethod
        def __reset_agent_cpu_quota():
            """
            Removes any CPUQuota on the agent

            NOTE: This resets the quota on the agent's default dropin file; any local overrides on the VM will take precedence
            over this setting.
            """
            log_cgroup_info("Resetting agent's CPUQuota", send_event=False)
            if CGroupConfigurator._Impl.__try_set_cpu_quota(''):  # setting an empty value resets to the default (infinity)
                log_cgroup_info('CPUQuota: {0}'.format(systemd.get_unit_property(systemd.get_agent_unit_name(), "CPUQuotaPerSecUSec")))

        # W0238: Unused private member `_Impl.__try_set_cpu_quota(quota)` (unused-private-member)
        @staticmethod
        def __try_set_cpu_quota(quota):  # pylint: disable=unused-private-member
            try:
                drop_in_file = os.path.join(systemd.get_agent_drop_in_path(), _DROP_IN_FILE_CPU_QUOTA)
                contents = _DROP_IN_FILE_CPU_QUOTA_CONTENTS_FORMAT.format(quota)
                if os.path.exists(drop_in_file):
                    with open(drop_in_file, "r") as file_:
                        if file_.read() == contents:
                            return True  # no need to update the file; return here to avoid doing a daemon-reload
                CGroupConfigurator._Impl.__create_unit_file(drop_in_file, contents)
            except Exception as exception:
                log_cgroup_warning('Failed to set CPUQuota: {0}'.format(ustr(exception)))
                return False
            try:
                log_cgroup_info("Executing systemctl daemon-reload...", send_event=False)
                shellutil.run_command(["systemctl", "daemon-reload"])
            except Exception as exception:
                log_cgroup_warning("daemon-reload failed (set quota): {0}".format(ustr(exception)))
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
            agent_cgroup_proc_names = []
            try:
                daemon = os.getppid()
                extension_handler = os.getpid()
                agent_commands = set()
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands = set()
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())
                agent_cgroup = self._cgroups_api.get_processes_in_cgroup(self._agent_cpu_cgroup_path)
                # get the running commands again in case new commands started or completed while we were fetching the processes in the cgroup;
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())

                for process in agent_cgroup:
                    agent_cgroup_proc_names.append(self.__format_process(process))
                    # Note that the agent uses systemd-run to start extensions; systemd-run belongs to the agent cgroup, though the extensions don't.
                    if process in (daemon, extension_handler) or process in systemd_run_commands:
                        continue
                    # check shell systemd_run process if above process check didn't catch it
                    if self._check_systemd_run_process(process):
                        continue
                    # systemd_run_commands contains the shell that started systemd-run, so we also need to check for the parent
                    if self._get_parent(process) in systemd_run_commands and self._get_command(
                            process) == 'systemd-run':
                        continue
                    # check if the process is a command started by the agent or a descendant of one of those commands
                    current = process
                    while current != 0 and current not in agent_commands:
                        current = self._get_parent(current)
                    # Verify if Process started by agent based on the marker found in process environment or process is in Zombie state.
                    # If so, consider it as valid process in agent cgroup.
                    if current == 0 and not (self.__is_process_descendant_of_the_agent(process) or self.__is_zombie_process(process)):
                        unexpected.append(self.__format_process(process))
                        if len(unexpected) >= 5:  # collect just a small sample
                            break
            except Exception as exception:
                log_cgroup_warning("Error checking the processes in the agent's cgroup: {0}".format(ustr(exception)))

            if len(unexpected) > 0:
                self._report_agent_cgroups_procs(agent_cgroup_proc_names, unexpected)
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
        def __is_zombie_process(pid):
            """
            Returns True if process is in Zombie state otherwise False.

            Ex: cat /proc/18171/stat
            18171 (python3) S 18103 18103 18103 0 -1 4194624 57736 64902 0 3
            """
            try:
                stat = '/proc/{0}/stat'.format(pid)
                if os.path.exists(stat):
                    with open(stat, "r") as stat_file:
                        return stat_file.read().split()[2] == 'Z'
            except Exception:
                pass
            return False

        @staticmethod
        def _check_systemd_run_process(process):
            """
            Returns True if process is shell systemd-run process started by agent otherwise False.

            Ex: sh,7345 -c systemd-run --unit=enable_7c5cab19-eb79-4661-95d9-9e5091bd5ae0 --scope --slice=azure-vmextensions-Microsoft.OSTCExtensions.VMAccessForLinux_1.5.11.slice /var/lib/waagent/Microsoft.OSTCExtensions.VMAccessForLinux-1.5.11/processes.sh
            """
            try:
                process_name = "UNKNOWN"
                cmdline = '/proc/{0}/cmdline'.format(process)
                if os.path.exists(cmdline):
                    with open(cmdline, "r") as cmdline_file:
                        process_name = "{0}".format(cmdline_file.read())
                match = re.search(r'systemd-run.*--unit=.*--scope.*--slice=azure-vmextensions.*', process_name)
                if match is not None:
                    return True
            except Exception:
                pass
            return False

        @staticmethod
        def _report_agent_cgroups_procs(agent_cgroup_proc_names, unexpected):
            for proc_name in unexpected:
                if 'UNKNOWN' in proc_name:
                    msg = "Agent includes following processes when UNKNOWN process found: {0}".format("\n".join([ustr(proc) for proc in agent_cgroup_proc_names]))
                    add_event(op=WALAEventOperation.CGroupsInfo, message=msg)

        @staticmethod
        def _check_agent_throttled_time(cgroup_metrics):
            for metric in cgroup_metrics:
                if metric.instance == AGENT_NAME_TELEMETRY and metric.counter == MetricsCounter.THROTTLED_TIME:
                    if metric.value > conf.get_agent_cpu_throttled_time_threshold():
                        raise CGroupsException("The agent has been throttled for {0} seconds".format(metric.value))

        def check_agent_memory_usage(self):
            if self.enabled() and self._agent_memory_cgroup:
                metrics = self._agent_memory_cgroup.get_tracked_metrics()
                current_usage = 0
                for metric in metrics:
                    if metric.counter == MetricsCounter.TOTAL_MEM_USAGE:
                        current_usage += metric.value
                    elif metric.counter == MetricsCounter.SWAP_MEM_USAGE:
                        current_usage += metric.value

                if current_usage > conf.get_agent_memory_quota():
                    raise AgentMemoryExceededException("The agent memory limit {0} bytes exceeded. The current reported usage is {1} bytes.".format(conf.get_agent_memory_quota(), current_usage))

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
                cpu_cgroup_path, memory_cgroup_path = self._cgroups_api.get_unit_cgroup_paths(unit_name)

                if cpu_cgroup_path is None:
                    log_cgroup_info("The CPU controller is not mounted or enabled; will not track resource usage", send_event=False)
                else:
                    CGroupsTelemetry.track_cgroup(CpuCgroup(unit_name, cpu_cgroup_path))

                if memory_cgroup_path is None:
                    log_cgroup_info("The Memory controller is not mounted or enabled; will not track resource usage", send_event=False)
                else:
                    CGroupsTelemetry.track_cgroup(MemoryCgroup(unit_name, memory_cgroup_path))

            except Exception as exception:
                log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(exception)), send_event=False)

        def stop_tracking_unit_cgroups(self, unit_name):
            """
            TODO: remove Memory cgroups from tracked list.
            """
            try:
                cpu_cgroup_path, memory_cgroup_path = self._cgroups_api.get_unit_cgroup_paths(unit_name)

                if cpu_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(CpuCgroup(unit_name, cpu_cgroup_path))

                if memory_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(MemoryCgroup(unit_name, memory_cgroup_path))

            except Exception as exception:
                log_cgroup_info("Failed to stop tracking resource usage for the extension service: {0}".format(ustr(exception)), send_event=False)

        def stop_tracking_extension_cgroups(self, extension_name):
            """
            TODO: remove extension Memory cgroups from tracked list
            """
            try:
                extension_slice_name = CGroupUtil.get_extension_slice_name(extension_name)
                cgroup_relative_path = os.path.join(_AZURE_VMEXTENSIONS_SLICE,
                                                    extension_slice_name)

                cpu_root_path, memory_root_path = self._cgroups_api.get_controller_root_paths()
                cpu_cgroup_path = os.path.join(cpu_root_path, cgroup_relative_path)
                memory_cgroup_path = os.path.join(memory_root_path, cgroup_relative_path)

                if cpu_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(CpuCgroup(extension_name, cpu_cgroup_path))

                if memory_cgroup_path is not None:
                    CGroupsTelemetry.stop_tracking(MemoryCgroup(extension_name, memory_cgroup_path))

            except Exception as exception:
                log_cgroup_info("Failed to stop tracking resource usage for the extension service: {0}".format(ustr(exception)), send_event=False)

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
                                                    CGroupUtil.get_extension_slice_name(extension_name))
                try:
                    cpu_quota = str(cpu_quota) + "%" if cpu_quota is not None else ""  # setting an empty value resets to the default (infinity)
                    if cpu_quota == "":
                        log_cgroup_info("CPUQuota not set for {0}".format(extension_name))
                    else:
                        log_cgroup_info("Ensuring the {0}'s CPUQuota is {1}".format(extension_name, cpu_quota))
                    slice_contents = _EXTENSION_SLICE_CONTENTS.format(extension_name=extension_name,
                                                                      cpu_quota=cpu_quota)
                    CGroupConfigurator._Impl.__create_unit_file(extension_slice_path, slice_contents)
                except Exception as exception:
                    log_cgroup_warning("Failed to set the extension {0} slice and quotas: {1}".format(extension_name,
                                        ustr(exception)))
                    CGroupConfigurator._Impl.__cleanup_unit_file(extension_slice_path)

        def remove_extension_slice(self, extension_name):
            """
            This method ensures that the extension slice gets removed from /lib/systemd/system if it exist
            Lastly stop the unit. This would ensure the cleanup the /sys/fs/cgroup controller paths
            """
            if self.enabled():
                unit_file_install_path = systemd.get_unit_file_install_path()
                extension_slice_name = CGroupUtil.get_extension_slice_name(extension_name)
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
                        drop_in_file_memory_accounting = os.path.join(drop_in_path,
                                                                      _DROP_IN_FILE_MEMORY_ACCOUNTING)
                        files_to_create.append(
                            (drop_in_file_memory_accounting, _DROP_IN_FILE_MEMORY_ACCOUNTING_CONTENTS))

                        cpu_quota = service.get('cpuQuotaPercentage', None)
                        if cpu_quota is not None:
                            cpu_quota = str(cpu_quota) + "%"
                            log_cgroup_info("Ensuring the {0}'s CPUQuota is {1}".format(service_name, cpu_quota))
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
                service_name = None
                try:
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
                    log_cgroup_warning('Failed to reset CPUQuota for {0} : {1}'.format(service_name, ustr(exception)))

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
                        drop_in_file_memory_accounting = os.path.join(drop_in_path,
                                                                      _DROP_IN_FILE_MEMORY_ACCOUNTING)
                        files_to_cleanup.append(drop_in_file_memory_accounting)
                        cpu_quota = service.get('cpuQuotaPercentage', None)
                        if cpu_quota is not None:
                            drop_in_file_cpu_quota = os.path.join(drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                            files_to_cleanup.append(drop_in_file_cpu_quota)

                        CGroupConfigurator._Impl.__cleanup_all_files(files_to_cleanup)
                        log_cgroup_info("Drop in files removed for {0}".format(service_name))

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
                            log_cgroup_warning(
                                'Failed to load manifest file ({0}): {1}'.format(manifest_path, e.strerror))
                        except ValueError:
                            log_cgroup_warning('Malformed manifest file ({0}).'.format(manifest_path))
            return extensions_services

    # unique instance for the singleton
    _instance = None

    @staticmethod
    def get_instance():
        if CGroupConfigurator._instance is None:
            CGroupConfigurator._instance = CGroupConfigurator._Impl()
        return CGroupConfigurator._instance
