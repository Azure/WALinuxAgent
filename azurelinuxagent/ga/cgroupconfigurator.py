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
from azurelinuxagent.ga.cgroupcontroller import AGENT_NAME_TELEMETRY, MetricsCounter
from azurelinuxagent.ga.cgroupapi import SystemdRunError, EXTENSION_SLICE_PREFIX, CGroupUtil, SystemdCgroupApiv2, \
    log_cgroup_info, log_cgroup_warning, create_cgroup_api, InvalidCgroupMountpointException
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.ga.cpucontroller import _CpuController
from azurelinuxagent.ga.memorycontroller import _MemoryController
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
LOGCOLLECTOR_CPU_QUOTA_FOR_V1_AND_V2 = "5%"
LOGCOLLECTOR_MEMORY_THROTTLE_LIMIT_FOR_V2 = "170M"
LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2 = 10
LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2 = 25 * 1024 ** 2  # 25Mb
LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2 = 155 * 1024 ** 2  # 155Mb

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
            self._agent_cgroup = None
            self._agent_memory_metrics = None
            self._check_cgroups_lock = threading.RLock()  # Protect the check_cgroups which is called from Monitor thread and main loop.
            self._unexpected_processes = {}

        def initialize(self):
            try:
                if self._initialized:
                    return
                # check whether cgroup monitoring is supported on the current distro
                self._cgroups_supported = self._check_cgroups_supported()
                if not self._cgroups_supported:
                    # If a distro is not supported, attempt to clean up any existing drop in files in case it was
                    # previously supported. It is necessary to cleanup in this scenario in case the OS hits any bugs on
                    # the kernel related to cgroups.
                    if not self.using_cgroup_v2():
                        log_cgroup_info("Agent will reset the quotas in case cgroup usage went from enabled to disabled")
                        self._reset_agent_cgroup_setup()
                    return

                # We check the agent unit 'Slice' property before setting up azure.slice. This check is done first
                # because the agent's Slice unit property will be 'azure.slice' if the slice drop-in file exists, even
                # though systemd has not moved the agent to azure.slice yet. Systemd will only move the agent to
                # azure.slice after a vm restart.
                agent_unit_name = systemd.get_agent_unit_name()
                agent_slice = systemd.get_unit_property(agent_unit_name, "Slice")
                if agent_slice not in (AZURE_SLICE, "system.slice"):
                    log_cgroup_warning("The agent is within an unexpected slice: {0}".format(agent_slice))
                    return

                # Before agent setup, cleanup the old agent setup (drop-in files) since new agent uses different approach(systemctl) to setup cgroups.
                self._cleanup_old_agent_setup()

                # Notes about slice setup:
                #   For machines where daemon version did not already create azure.slice, the
                #   agent creates azure.slice and the agent unit Slice drop-in file(without daemon-reload), but systemd does not move the agent
                #   unit to azure.slice until vm restart. It is ok to enable cgroup usage in this case if agent is
                #   running in system.slice.
                self._setup_azure_slice()

                # Log mount points/root paths for cgroup controllers
                self._cgroups_api.log_root_paths()

                # Get agent cgroup
                self._agent_cgroup = self._cgroups_api.get_unit_cgroup(unit_name=agent_unit_name, cgroup_name=AGENT_NAME_TELEMETRY)

                if conf.get_cgroup_disable_on_process_check_failure() and self._check_fails_if_processes_found_in_agent_cgroup_before_enable(agent_slice):
                    reason = "Found unexpected processes in the agent cgroup before agent enable cgroups."
                    self.disable(reason, DisableCgroups.ALL)
                    return

                # Get controllers to track
                agent_controllers = self._agent_cgroup.get_controllers(expected_relative_path=os.path.join(agent_slice, agent_unit_name))
                if len(agent_controllers) > 0:
                    self.enable()
                    self._enable_accounting(agent_unit_name)

                for controller in agent_controllers:
                    for prop in controller.get_unit_properties():
                        log_cgroup_info('Agent {0} unit property value: {1}'.format(prop, systemd.get_unit_property(systemd.get_agent_unit_name(), prop)))
                    if isinstance(controller, _CpuController):
                        self._set_cpu_quota(agent_unit_name, conf.get_agent_cpu_quota())
                    elif isinstance(controller, _MemoryController):
                        self._agent_memory_metrics = controller
                    CGroupsTelemetry.track_cgroup_controller(controller)

            except Exception as exception:
                log_cgroup_warning("Error initializing cgroups: {0}".format(ustr(exception)))
            finally:
                log_cgroup_info('Agent cgroups enabled: {0}'.format(self._agent_cgroups_enabled))
                self._initialized = True

        def _check_cgroups_supported(self):
            distro_supported = CGroupUtil.distro_supported()
            if not distro_supported:
                log_cgroup_info("Cgroups is not currently supported on {0}".format(get_distro()), send_event=True)
                return False

            if not systemd.is_systemd():
                log_cgroup_warning("systemd was not detected on {0}".format(get_distro()), send_event=True)
                log_cgroup_info("Cgroups won't be supported on non-systemd systems", send_event=True)
                return False

            if not self._check_no_legacy_cgroups():
                log_cgroup_warning("The daemon's PID was added to a legacy cgroup; will not enable cgroups.", send_event=True)
                return False

            try:
                self._cgroups_api = create_cgroup_api()
                log_cgroup_info("Using cgroup {0} for resource enforcement and monitoring".format(self._cgroups_api.get_cgroup_version()))
            except InvalidCgroupMountpointException as e:
                # Systemd mounts the cgroup file system at '/sys/fs/cgroup'. Previously, the agent supported cgroup
                # usage if a user mounted the cgroup filesystem elsewhere. The agent no longer supports that
                # scenario. Cleanup any existing drop in files in case the agent previously supported cgroups on
                # this machine.
                log_cgroup_warning(
                    "The agent does not support cgroups if the default systemd mountpoint is not being used: {0}".format(
                        ustr(e)), send_event=True)
                return False
            except CGroupsException as e:
                log_cgroup_warning("Unable to determine which cgroup version to use: {0}".format(ustr(e)),
                                   send_event=True)
                return False

            if self.using_cgroup_v2():
                log_cgroup_info("Agent and extensions resource enforcement and monitoring is not currently supported on cgroup v2", send_event=True)
                return False

            return True

        @staticmethod
        def _check_no_legacy_cgroups():
            """
            Older versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent. When running
            under systemd this could produce invalid resource usage data. Cgroups should not be enabled under this condition.
            """
            legacy_cgroups = CGroupUtil.cleanup_legacy_cgroups()
            if legacy_cgroups > 0:
                return False
            return True

        @staticmethod
        def _cleanup_old_agent_setup():
            """
            New agent switching to use systemctl cmd instead of drop-files for desired configuration. So, cleaning up the old drop-in files.
            We will keep cleanup code for few agents, until we determine all vms moved to new agent version.
            """

            # Older agents used to create this slice, but it was never used. Cleanup the file.
            CGroupConfigurator._Impl._cleanup_unit_file("/etc/systemd/system/system-walinuxagent.extensions.slice")

            unit_file_install_path = systemd.get_unit_file_install_path()
            logcollector_slice = os.path.join(unit_file_install_path, LOGCOLLECTOR_SLICE)
            agent_drop_in_path = systemd.get_agent_drop_in_path()
            agent_drop_in_file_cpu_accounting = os.path.join(agent_drop_in_path, _DROP_IN_FILE_CPU_ACCOUNTING)
            agent_drop_in_file_memory_accounting = os.path.join(agent_drop_in_path, _DROP_IN_FILE_MEMORY_ACCOUNTING)
            agent_drop_in_file_cpu_quota = os.path.join(agent_drop_in_path, _DROP_IN_FILE_CPU_QUOTA)

            # New agent will setup limits for scope instead slice, so removing existing logcollector slice.
            CGroupConfigurator._Impl._cleanup_unit_file(logcollector_slice)

            # Cleanup the old drop-in files, new agent will use systemdctl set-property to enable accounting and limits
            CGroupConfigurator._Impl._cleanup_unit_file(agent_drop_in_file_cpu_accounting)

            CGroupConfigurator._Impl._cleanup_unit_file(agent_drop_in_file_memory_accounting)

            CGroupConfigurator._Impl._cleanup_unit_file(agent_drop_in_file_cpu_quota)

        @staticmethod
        def _setup_azure_slice():
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
            """

            unit_file_install_path = systemd.get_unit_file_install_path()
            azure_slice = os.path.join(unit_file_install_path, AZURE_SLICE)
            vmextensions_slice = os.path.join(unit_file_install_path, _VMEXTENSIONS_SLICE)
            agent_unit_file = systemd.get_agent_unit_file()
            agent_drop_in_path = systemd.get_agent_drop_in_path()
            agent_drop_in_file_slice = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_SLICE)

            files_to_create = []

            if not os.path.exists(azure_slice):
                files_to_create.append((azure_slice, _AZURE_SLICE_CONTENTS))

            if not os.path.exists(vmextensions_slice):
                files_to_create.append((vmextensions_slice, _VMEXTENSIONS_SLICE_CONTENTS))

            if fileutil.findre_in_file(agent_unit_file, r"Slice=") is not None:
                CGroupConfigurator._Impl._cleanup_unit_file(agent_drop_in_file_slice)
            else:
                if not os.path.exists(agent_drop_in_file_slice):
                    files_to_create.append((agent_drop_in_file_slice, _AGENT_DROP_IN_FILE_SLICE_CONTENTS))

            if len(files_to_create) > 0:
                # create the unit files, but if 1 fails remove all and return
                try:
                    for path, contents in files_to_create:
                        CGroupConfigurator._Impl._create_unit_file(path, contents)
                except Exception as exception:
                    log_cgroup_warning("Failed to create unit files for the azure slice: {0}".format(ustr(exception)))
                    for unit_file in files_to_create:
                        CGroupConfigurator._Impl._cleanup_unit_file(unit_file)
                        return

        def _reset_agent_cgroup_setup(self):
            try:
                agent_drop_in_path = systemd.get_agent_drop_in_path()
                if os.path.exists(agent_drop_in_path) and os.path.isdir(agent_drop_in_path):
                    files_to_cleanup = []
                    agent_drop_in_file_slice = os.path.join(agent_drop_in_path, _AGENT_DROP_IN_FILE_SLICE)
                    files_to_cleanup.append(agent_drop_in_file_slice)
                    agent_drop_in_file_cpu_accounting = os.path.join(agent_drop_in_path,
                                                                     _DROP_IN_FILE_CPU_ACCOUNTING)
                    files_to_cleanup.append(agent_drop_in_file_cpu_accounting)
                    agent_drop_in_file_memory_accounting = os.path.join(agent_drop_in_path,
                                                                        _DROP_IN_FILE_MEMORY_ACCOUNTING)
                    files_to_cleanup.append(agent_drop_in_file_memory_accounting)
                    agent_drop_in_file_cpu_quota = os.path.join(agent_drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                    files_to_cleanup.append(agent_drop_in_file_cpu_quota)

                    if len(files_to_cleanup) > 0:
                        log_cgroup_info("Found drop-in files; attempting agent cgroup setup cleanup", send_event=False)
                        self._cleanup_all_files(files_to_cleanup)
                        self._reset_cpu_quota(systemd.get_agent_unit_name())

            except Exception as err:
                logger.warn("Error while resetting the quotas: {0}".format(err))

        @staticmethod
        def _enable_accounting(unit_name):
            """
            Enable CPU and Memory accounting for the unit
            """
            try:
                # since we don't use daemon-reload and drop-files for accounting, so it will be enabled with systemctl set-property
                accounting_properties = ("CPUAccounting", "MemoryAccounting")
                values = ("yes", "yes")
                log_cgroup_info("Enabling accounting properties for the agent: {0}".format(accounting_properties))
                systemd.set_unit_run_time_properties(unit_name, accounting_properties, values)
            except Exception as exception:
                log_cgroup_warning("Failed to set accounting properties for the agent: {0}".format(ustr(exception)))

        # W0238: Unused private member `_Impl.__create_unit_file(path, contents)` (unused-private-member)
        @staticmethod
        def _create_unit_file(path, contents):  # pylint: disable=unused-private-member
            parent, _ = os.path.split(path)
            if not os.path.exists(parent):
                fileutil.mkdir(parent, mode=0o755)
            exists = os.path.exists(path)
            fileutil.write_file(path, contents)
            log_cgroup_info("{0} {1}".format("Updated" if exists else "Created", path))

        # W0238: Unused private member `_Impl.__cleanup_unit_file(path)` (unused-private-member)
        @staticmethod
        def _cleanup_unit_file(path):  # pylint: disable=unused-private-member
            if os.path.exists(path):
                try:
                    os.remove(path)
                    log_cgroup_info("Removed {0}".format(path))
                except Exception as exception:
                    log_cgroup_warning("Failed to remove {0}: {1}".format(path, ustr(exception)))

        @staticmethod
        def _cleanup_all_files(files_to_cleanup):
            for path in files_to_cleanup:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        log_cgroup_info("Removed {0}".format(path))
                    except Exception as exception:
                        log_cgroup_warning("Failed to remove {0}: {1}".format(path, ustr(exception)))

        @staticmethod
        def _create_all_files(files_to_create):
            # create the unit files, but if 1 fails remove all and return
            try:
                for path, contents in files_to_create:
                    CGroupConfigurator._Impl._create_unit_file(path, contents)
            except Exception as exception:
                log_cgroup_warning("Failed to create unit files : {0}".format(ustr(exception)))
                for unit_file in files_to_create:
                    CGroupConfigurator._Impl._cleanup_unit_file(unit_file)
                return

        @staticmethod
        def _get_current_cpu_quota(unit_name):
            """
            Calculate the CPU percentage from CPUQuotaPerSecUSec for given unit.
            Params:
                cpu_quota_per_sec_usec (str): The value of CPUQuotaPerSecUSec (e.g., "1s", "500ms", "500us", or "infinity").

            Returns:
                str: CPU percentage, or 'infinity' or 'unknown' if we can't determine the value.
            """
            try:
                cpu_quota_per_sec_usec = systemd.get_unit_property(unit_name, "CPUQuotaPerSecUSec").strip().lower()
                if cpu_quota_per_sec_usec == "infinity":
                    return cpu_quota_per_sec_usec  # No limit on CPU usage

                # Parse the value based on the suffix
                elif cpu_quota_per_sec_usec.endswith("us"):
                    # Directly use the microseconds value
                    cpu_quota_us = float(cpu_quota_per_sec_usec[:-2])
                elif cpu_quota_per_sec_usec.endswith("ms"):
                    # Convert milliseconds to microseconds
                    cpu_quota_us = float(cpu_quota_per_sec_usec[:-2]) * 1000
                elif cpu_quota_per_sec_usec.endswith("s"):
                    # Convert seconds to microseconds
                    cpu_quota_us = float(cpu_quota_per_sec_usec[:-1]) * 1000000
                else:
                    raise ValueError("Invalid format. Expected 's', 'ms', 'us', or 'infinity'.")

                # Calculate CPU percentage
                cpu_percentage = (cpu_quota_us / 1000000) * 100
                return "{:g}%".format(cpu_percentage)  # :g Removes trailing zeros after decimal point
            except Exception as e:
                log_cgroup_warning("Error parsing current CPUQuotaPerSecUSec: {0}".format(ustr(e)))
                return "unknown"

        def supported(self):
            return self._cgroups_supported

        def enabled(self):
            return self._agent_cgroups_enabled or self._extensions_cgroups_enabled

        def agent_enabled(self):
            return self._agent_cgroups_enabled

        def extensions_enabled(self):
            return self._extensions_cgroups_enabled

        def using_cgroup_v2(self):
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
                self._reset_cpu_quota(systemd.get_agent_unit_name())
                extension_services = self.get_extension_services_list()
                for extension in extension_services:
                    log_cgroup_info("Resetting extension : {0} and it's services: {1} Quota".format(extension, extension_services[extension]), send_event=False)
                    self.reset_extension_quota(extension_name=extension)
                    self.reset_extension_services_quota(extension_services[extension])
                CGroupsTelemetry.reset()
                self._agent_cgroups_enabled = False
                self._extensions_cgroups_enabled = False
            elif disable_cgroups == DisableCgroups.AGENT:  # disable agent
                self._reset_cpu_quota(systemd.get_agent_unit_name())
                agent_controllers = self._agent_cgroup.get_controllers()
                for controller in agent_controllers:
                    if isinstance(controller, _CpuController):
                        CGroupsTelemetry.stop_tracking(controller)
                        break
                self._agent_cgroups_enabled = False

            log_cgroup_warning("Disabling resource usage monitoring. Reason: {0}".format(reason), op=WALAEventOperation.CGroupsDisabled)

        @staticmethod
        def _set_cpu_quota(unit_name, quota):
            """
            Sets CPU quota to the given percentage (100% == 1 CPU)

            NOTE: This is done using a systemtcl set-property --runtime; any local overrides in /etc folder on the VM will take precedence
            over this setting.
            """
            quota_percentage = "{0}%".format(quota)
            log_cgroup_info("Setting {0}'s CPUQuota to {1}".format(unit_name, quota_percentage))
            CGroupConfigurator._Impl._try_set_cpu_quota(unit_name, quota_percentage)

        @staticmethod
        def _reset_cpu_quota(unit_name):
            """
            Removes any CPUQuota on the agent

            NOTE: This resets the quota on the agent's default dropin file; any local overrides on the VM will take precedence
            over this setting.
            """
            log_cgroup_info("Resetting {0}'s CPUQuota".format(unit_name), send_event=False)
            CGroupConfigurator._Impl._try_set_cpu_quota(unit_name, "infinity") # systemd expresses no-quota as infinity, following the same convention
            log_cgroup_info('Current CPUQuota: {0}'.format(systemd.get_unit_property(unit_name, "CPUQuotaPerSecUSec")))

        # W0238: Unused private member `_Impl.__try_set_cpu_quota(quota)` (unused-private-member)
        @staticmethod
        def _try_set_cpu_quota(unit_name, quota):  # pylint: disable=unused-private-member
            try:
                current_cpu_quota = CGroupConfigurator._Impl._get_current_cpu_quota(unit_name)
                if current_cpu_quota == quota:
                    return
                quota = quota if quota != "infinity" else ""  # no-quota expressed as empty string while setting property
                systemd.set_unit_run_time_property(unit_name, "CPUQuota", quota)
            except Exception as exception:
                log_cgroup_warning('Failed to set CPUQuota: {0}'.format(ustr(exception)))

        def _check_fails_if_processes_found_in_agent_cgroup_before_enable(self, agent_slice):
            """
            This check ensures that before we enable the agent's cgroups, there are no unexpected processes in the agent's cgroup already.

            The issue we observed that long running extension processes may be in agent cgroups if agent goes this cycle enabled(1)->disabled(2)->enabled(3).
            1. Agent cgroups enabled in some version
            2. Disabled agent cgroups due to check_cgroups regular check. Once we disable the cgroups we don't run the extensions in it's own slice, so they will be in agent cgroups.
            3. When ext_hanlder restart and enable the cgroups again, already running processes from step 2 still be in agent cgroups. This may cause the extensions run with agent limit.
            """
            if agent_slice not in (AZURE_SLICE, "system.slice"):
                return False
            try:
                log_cgroup_info("Checking for unexpected processes in the agent's cgroup before enabling cgroups")
                self._check_processes_in_agent_cgroup(True)
            except CGroupsException as exception:
                log_cgroup_warning(ustr(exception))
                return True

            return False

        def check_cgroups(self, cgroup_metrics):
            self._check_cgroups_lock.acquire()
            try:
                if not self.enabled():
                    return

                errors = []

                process_check_success = False
                try:
                    self._check_processes_in_agent_cgroup(False)
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

        def _check_processes_in_agent_cgroup(self, report_immediately):
            """
            Verifies that the agent's cgroup includes only the current process, its parent, commands started using shellutil and instances of systemd-run
            (those processes correspond, respectively, to the extension handler, the daemon, commands started by the extension handler, and the systemd-run
            commands used to start extensions on their own cgroup).
            Other processes started by the agent (e.g. extensions) and processes not started by the agent (e.g. services installed by extensions) are reported
            as unexpected, since they should belong to their own cgroup.

            Raises a CGroupsException only when current unexpected process seen last time.

            report_immediately - flag to switch to old behavior and report immediately if any unexpected process found.

            Note: Process check was added as conservative approach before cgroups feature stable. Now it's producing noise due to race issues, some of those issues are extra process before systemd move to new cgroup or process about to die.
            So now changing the behavior to raise an issue only when we see the same unexpected process on last check. Later we will remove the check if no issues reported.
            """
            current_unexpected = {}
            agent_cgroup_proc_names = []
            report = []

            try:
                daemon = os.getppid()
                extension_handler = os.getpid()
                agent_commands = set()
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands = set()
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())
                agent_cgroup_proccesses = self._agent_cgroup.get_processes()
                # get the running commands again in case new commands started or completed while we were fetching the processes in the cgroup;
                agent_commands.update(shellutil.get_running_commands())
                systemd_run_commands.update(self._cgroups_api.get_systemd_run_commands())

                for process in agent_cgroup_proccesses:
                    agent_cgroup_proc_names.append(self._format_process(process))
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
                    if current == 0 and not (self._is_process_descendant_of_the_agent(process) or self._is_zombie_process(process)):
                        current_unexpected[process] = self._format_process(process)
                if report_immediately:
                    report = current_unexpected.values()
                else:
                    for process in current_unexpected:
                        if process in self._unexpected_processes:
                            report.append(current_unexpected[process])
                        if len(report) >= 5:  # collect just a small sample
                            break
                    self._unexpected_processes = current_unexpected
            except Exception as exception:
                log_cgroup_warning("Error checking the processes in the agent's cgroup: {0}".format(ustr(exception)))

            if len(report) > 0:
                self._report_agent_cgroups_procs(agent_cgroup_proc_names, report)
                raise CGroupsException("The agent's cgroup includes unexpected processes: {0}".format(report))

        def get_logcollector_unit_properties(self):
            """
            Returns the systemd unit properties for the log collector process.

            Each property should be explicitly set (even if already included in the log collector slice) for the log
            collector process to run in the transient scope directory with the expected accounting and limits.
            """
            logcollector_properties = ["--property=CPUAccounting=yes", "--property=MemoryAccounting=yes", "--property=CPUQuota={0}".format(LOGCOLLECTOR_CPU_QUOTA_FOR_V1_AND_V2)]
            if not self.using_cgroup_v2():
                return logcollector_properties
            # Memory throttling limit is used when running log collector on v2 machines using the 'MemoryHigh' property.
            # We do not use a systemd property to enforce memory on V1 because it invokes the OOM killer if the limit
            # is exceeded.
            logcollector_properties.append("--property=MemoryHigh={0}".format(LOGCOLLECTOR_MEMORY_THROTTLE_LIMIT_FOR_V2))
            return logcollector_properties

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
        def _format_process(pid):
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
        def _is_process_descendant_of_the_agent(pid):
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
        def _is_zombie_process(pid):
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
            if self.enabled() and self._agent_memory_metrics is not None:
                metrics = self._agent_memory_metrics.get_tracked_metrics()
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
            if self.enabled():
                try:
                    cgroup = self._cgroups_api.get_unit_cgroup(unit_name, unit_name)
                    controllers = cgroup.get_controllers()

                    for controller in controllers:
                        CGroupsTelemetry.track_cgroup_controller(controller)

                except Exception as exception:
                    log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(exception)), send_event=False)

        def stop_tracking_unit_cgroups(self, unit_name):
            if self.enabled():
                try:
                    cgroup = self._cgroups_api.get_unit_cgroup(unit_name, unit_name)
                    controllers = cgroup.get_controllers()

                    for controller in controllers:
                        CGroupsTelemetry.stop_tracking(controller)

                except Exception as exception:
                    log_cgroup_info("Failed to stop tracking resource usage for the extension service: {0}".format(ustr(exception)), send_event=False)

        def stop_tracking_extension_cgroups(self, extension_name):
            if self.enabled():
                try:
                    extension_slice_name = CGroupUtil.get_extension_slice_name(extension_name)
                    cgroup_relative_path = os.path.join(_AZURE_VMEXTENSIONS_SLICE, extension_slice_name)

                    cgroup = self._cgroups_api.get_cgroup_from_relative_path(relative_path=cgroup_relative_path,
                                                                             cgroup_name=extension_name)
                    controllers = cgroup.get_controllers()
                    for controller in controllers:
                        CGroupsTelemetry.stop_tracking(controller)

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

        @staticmethod
        def _get_unit_properties_requiring_update(unit_name, cpu_quota=""):
            """
            Check if the cgroups setup is completed for the unit and return the properties that need an update.
            """
            properties_to_update = ()
            properties_values = ()
            cpu_accounting = systemd.get_unit_property(unit_name, "CPUAccounting")
            if cpu_accounting != "yes":
                properties_to_update += ("CPUAccounting",)
                properties_values += ("yes",)
            memory_accounting = systemd.get_unit_property(unit_name, "MemoryAccounting")
            if memory_accounting != "yes":
                properties_to_update += ("MemoryAccounting",)
                properties_values += ("yes",)
            current_cpu_quota = CGroupConfigurator._Impl._get_current_cpu_quota(unit_name)
            if current_cpu_quota != cpu_quota:
                properties_to_update += ("CPUQuota",)
                # no-quota expressed as empty string while setting property
                cpu_quota = cpu_quota if cpu_quota != "infinity" else ""
                properties_values += (cpu_quota,)
            return properties_to_update, properties_values

        def setup_extension_slice(self, extension_name, cpu_quota):
            """
            Each extension runs under its own slice (Ex "Microsoft.CPlat.Extension.slice"). All the slices for
            extensions are grouped under "azure-vmextensions.slice.

            This method ensures that the desired configuration created for the extension slice using systemdctl set-property.
            TODO: set memory quotas
            """
            if self.enabled():
                extension_slice = CGroupUtil.get_extension_slice_name(extension_name)
                try:
                    # clean up the old slice from the disk, new agent use systemdctl set-property
                    unit_file_install_path = systemd.get_unit_file_install_path()
                    extension_slice_path = os.path.join(unit_file_install_path, extension_slice)
                    CGroupConfigurator._Impl._cleanup_unit_file(extension_slice_path)

                    # clean up the old-old slice(includes version in the name) from the disk
                    old_extension_slice_path = os.path.join(unit_file_install_path,
                                                            CGroupUtil.get_extension_slice_name(extension_name,
                                                                                                old_slice=True))
                    if os.path.exists(old_extension_slice_path):
                        CGroupConfigurator._Impl._cleanup_unit_file(old_extension_slice_path)

                    cpu_quota = "{0}%".format(
                        cpu_quota) if cpu_quota is not None else "infinity"  # following systemd convention for no-quota (infinity)
                    properties_to_update, properties_values = self._get_unit_properties_requiring_update(extension_slice, cpu_quota)

                    if len(properties_to_update) > 0:
                        if cpu_quota == "infinity":
                            log_cgroup_info("CPUQuota not set for {0}".format(extension_name))
                        else:
                            log_cgroup_info("Setting {0}'s CPUQuota to {1}".format(extension_name, cpu_quota))

                        log_cgroup_info("Setting up the resource properties: {0} for {1}".format(properties_to_update, extension_slice))
                        systemd.set_unit_run_time_properties(extension_slice, properties_to_update, properties_values)

                except Exception as exception:
                    log_cgroup_warning("Failed to set the extension {0} slice and quotas: {1}".format(extension_slice,
                                        ustr(exception)))

        def reset_extension_quota(self, extension_name):
            """
            Removes any CPUQuota on the extension

            NOTE: This resets the quota on the extension's slice; any local overrides on the VM will take precedence
            over this setting.
            TODO: reset memory quotas
            """
            if self.enabled():
                self._reset_cpu_quota(CGroupUtil.get_extension_slice_name(extension_name))

        def set_extension_services_cpu_memory_quota(self, services_list):
            """
            Each extension service will have name, systemd path and it's quotas.
            This method ensure limits set with systemtctl at runtime
            TODO: set memory quotas
            """
            if self.enabled() and services_list is not None:
                for service in services_list:
                    service_name = service.get('name', None)
                    unit_file_path = systemd.get_unit_file_install_path()
                    if service_name is not None and unit_file_path is not None:
                        # remove drop files from disk, new agent use systemdctl set-property
                        files_to_remove = []
                        drop_in_path = os.path.join(unit_file_path, "{0}.d".format(service_name))
                        drop_in_file_cpu_accounting = os.path.join(drop_in_path,
                                                                   _DROP_IN_FILE_CPU_ACCOUNTING)
                        files_to_remove.append(drop_in_file_cpu_accounting)
                        drop_in_file_memory_accounting = os.path.join(drop_in_path,
                                                                      _DROP_IN_FILE_MEMORY_ACCOUNTING)
                        files_to_remove.append(drop_in_file_memory_accounting)

                        drop_in_file_cpu_quota = os.path.join(drop_in_path, _DROP_IN_FILE_CPU_QUOTA)
                        files_to_remove.append(drop_in_file_cpu_quota)
                        self._cleanup_all_files(files_to_remove)

                        cpu_quota = service.get('cpuQuotaPercentage')
                        cpu_quota = "{0}%".format(cpu_quota) if cpu_quota is not None else "infinity"  # following systemd convention for no-quota (infinity)
                        properties_to_update, properties_values = self._get_unit_properties_requiring_update(service_name, cpu_quota)
                        # If systemd is unaware of extension services and not loaded in the system yet, we get error while setting quotas. Hence, added unit loaded check.
                        if systemd.is_unit_loaded(service_name) and len(properties_to_update) > 0:
                            if cpu_quota != "infinity":
                                log_cgroup_info("Setting {0}'s CPUQuota to {1}".format(service_name, cpu_quota))
                            else:
                                log_cgroup_info("CPUQuota not set for {0}".format(service_name))
                            log_cgroup_info("Setting up resource properties: {0} for {1}" .format(properties_to_update, service_name))
                            try:
                                systemd.set_unit_run_time_properties(service_name, properties_to_update, properties_values)
                            except Exception as exception:
                                log_cgroup_warning("Failed to set the quotas for {0}: {1}".format(service_name, ustr(exception)))

        def reset_extension_services_quota(self, services_list):
            """
            Removes any CPUQuota on the extension service

            NOTE: This resets the quota on the extension service's default; any local overrides on the VM will take precedence
            over this setting.
            TODO: reset memory quotas
            """
            if self.enabled() and services_list is not None:
                service_name = None
                try:
                    for service in services_list:
                        service_name = service.get('name', None)
                        if service_name is not None and systemd.is_unit_loaded(service_name):
                            self._reset_cpu_quota(service_name)
                except Exception as exception:
                    log_cgroup_warning('Failed to reset for {0} : {1}'.format(service_name, ustr(exception)))

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
