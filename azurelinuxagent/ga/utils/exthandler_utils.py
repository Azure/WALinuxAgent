# Microsoft Azure Linux Agent
#
# Copyright 2019 Microsoft Corporation
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


from azurelinuxagent.common import logger as logger, conf
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import ExtensionHandlerConfigurationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME

MEMORY_OOM_KILL_OPTIONS = ["enabled", "disabled"]
DEFAULT_CORES_COUNT = -1

AGENT_CGROUP_NAME = "WALinuxAgent"
DEFAULT_CPU_LIMIT_AGENT = 10.0
DEFAULT_CPU_LIMIT_EXT = 40.0
DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN = 256.0  # mb, applies to agent and extensions
DEFAULT_MEM_LIMIT_MAX_MB_FOR_AGENT = 512.0  # mb, applies to agent only
DEFAULT_MEM_LIMIT_PCT_FOR_EXTN = 15.0  # percent, applies to extensions

CGROUPS_ENFORCE_DEFAULT_LIMITS = False  # Currently, we don't want to enforce defaults as well.


class HandlerConfiguration(object):
    @staticmethod
    def send_handler_configuration_event(name=AGENT_NAME, message="", operation=WALAEventOperation.Unknown,
                                         is_success=True, log_event=True):
        if message:
            add_event(name=name, message=message, op=operation, is_success=is_success, log_event=log_event)

    def __init__(self, handler_config_json, name=None):
        self._data = handler_config_json
        self._name = name
        self.resource_config = None
        self.resource_limits = None

        try:
            if handler_config_json is None:
                raise ExtensionHandlerConfigurationError('Malformed handler configuration file. '
                                                  'No data present')
            if "handlerConfiguration" not in handler_config_json:
                raise ExtensionHandlerConfigurationError('Malformed handler configuration file. '
                                                  '"HandlerConfiguration" key not present')
            if "linux" not in handler_config_json['handlerConfiguration']:
                raise ExtensionHandlerConfigurationError('No linux configurations present in '
                                                  'HandlerConfiguration')

            try:
                self.resource_config = ExtensionResourcesConfiguration(self.get_linux_configurations())
            except ExtensionHandlerConfigurationError as e:
                raise e

            if self.resource_config or CGROUPS_ENFORCE_DEFAULT_LIMITS:
                self.resource_limits = CGroupsLimits(self._name, self.resource_config)

        except ExtensionHandlerConfigurationError as e:
            logger.warn(ustr(e))
            self.send_handler_configuration_event(message=ustr(e), is_success=False, log_event=False,
                                                                  operation=WALAEventOperation.HandlerConfiguration)

    def get_name(self):
        return self._data.get("name", None)

    def get_version(self):
        return self._data.get("version", None)

    def get_linux_configurations(self):
        return self._data['handlerConfiguration']['linux']

    def get_resource_configurations(self):
        return self.resource_config

    def get_resource_limits(self):
        return self.resource_limits


class ExtensionResourcesConfiguration(object):
    def __init__(self, resource_configuration):
        self._data = resource_configuration["resources"]
        self.cpu_limits = None
        self.memory_limits = None

        try:
            if "cpu" not in self._data and "memory" not in self._data:
                raise ExtensionHandlerConfigurationError('No "cpu" node present in '
                                                  'ResourceConfiguration')

            if "cpu" in self._data:
                self.cpu_limits = CpuLimits(self._data["cpu"])
            if "memory" in self._data:
                self.memory_limits = MemoryLimits(self._data["memory"])
        except ExtensionHandlerConfigurationError as e:
            logger.warn(ustr(e))
            HandlerConfiguration.send_handler_configuration_event(message=ustr(e), is_success=False,
                                                                  log_event=False,
                                                                  operation=WALAEventOperation.HandlerConfiguration)
            raise e

    def get_cpu_limits_for_extension(self):
        return self.cpu_limits

    def get_memory_limits_for_extension(self):
        return self.memory_limits


class CpuLimits(object):
    def __init__(self, cpu_node):
        self.cpu_limits = []
        self.cores = []

        for cpu_info in cpu_node:
            # integers and > 0.
            if "cores" not in cpu_info or "limit_percentage" not in cpu_info:
                raise ExtensionHandlerConfigurationError("Malformed CPU limit node in HandlerConfiguration")
            self.cpu_limits.append(CpuLimitInstance(cpu_info["cores"], cpu_info["limit_percentage"]))
            self.cores.append(cpu_info["cores"])

        if DEFAULT_CORES_COUNT not in self.cores:
            raise ExtensionHandlerConfigurationError("Default CPU limit not set."
                                              " Core configuration for {0} not present".format(DEFAULT_CORES_COUNT))

        self.cpu_limits = sorted(self.cpu_limits)

    def __str__(self):
        return self.cpu_limits.__str__()


class CpuLimitInstance(object):
    def __init__(self, cores, limit_percentage):
        if type(cores) is not int:
            raise ExtensionHandlerConfigurationError(
                "Incorrect types for CPU values | field - {0}/ value - {1}/ type - {2}".format("cores", cores,
                                                                                               type(cores)))

        if type(limit_percentage) is not float and type(limit_percentage) is not int:
            raise ExtensionHandlerConfigurationError(
                "Incorrect types for CPU values | field - {0}/ value - {1}/ type - {2}".format("limit_percentage",
                                                                                               limit_percentage,
                                                                                               type(limit_percentage)))

        if cores != DEFAULT_CORES_COUNT and cores < 1:
            raise ExtensionHandlerConfigurationError(
                "CPU cores value incorrect | field - {0}, {1}/ value - {2}, {3}".format("cores", "limit_percentage",
                                                                                        cores, limit_percentage))

        if limit_percentage > 100 or limit_percentage < 1:
            raise ExtensionHandlerConfigurationError(
                "CPU cores limit_percentage out of range | "
                "field - {0}, {1}/ value - {2}, {3}".format("cores",
                                                            "limit_percentage",
                                                            cores,
                                                            limit_percentage))
        self.cores = int(cores)
        self.limit_percentage = float(limit_percentage)

    def __eq__(self, other):
        return self.cores == other.cores

    def __lt__(self, other):
        return self.cores < other.cores

    def __gt__(self, other):
        return self.cores > other.cores

    def __str__(self):
        return {"cores": self.cores, "limit_percentage": self.limit_percentage}.__str__()

    def __repr__(self):
        return {"cores": self.cores, "limit_percentage": self.limit_percentage}.__str__()


class MemoryLimits(object):
    def __init__(self, memory_node):
        if "max_limit_MBs" in memory_node and "max_limit_percentage" in memory_node:
            self.max_limit_percentage = memory_node.get("max_limit_percentage", None)
            self.max_limit_MBs = memory_node.get("max_limit_MBs", None)

            if type(self.max_limit_percentage) is not float and type(self.max_limit_percentage) is not int:
                raise ExtensionHandlerConfigurationError(
                    "Incorrect types for Memory values - field - {0} | value - {1} | type - {2}".format(
                        "max_limit_percentage",
                        self.max_limit_percentage,
                        type(self.max_limit_percentage)))

            if type(self.max_limit_MBs) is not float and type(self.max_limit_MBs) is not int:
                raise ExtensionHandlerConfigurationError(
                    "Incorrect types for Memory values - field - {0} | value - {1} | type - {2}".format(
                        "max_limit_MBs", self.max_limit_MBs, type(self.max_limit_MBs)))

            if self.max_limit_percentage > 100 or self.max_limit_percentage < 1:
                raise ExtensionHandlerConfigurationError(
                    "Incorrect types for Memory values - field - {0} | value - {1} | type - {2}".format(
                        "max_limit_MBs", self.max_limit_MBs, type(self.max_limit_MBs)))
        else:
            raise ExtensionHandlerConfigurationError(
                "Default max memory limit not set. max_limit_MBs: {0}, max_limit_percentage: {1}".format(
                    memory_node.get("max_limit_MBs", None), memory_node.get("max_limit_percentage", None)))

        self.memory_pressure_warning = memory_node.get("memory_pressure_warning", None)
        self.memory_oom_kill = None  # default will be set in compute_default for memory flags.

        if "memory_oom_kill" in memory_node:
            if memory_node["memory_oom_kill"].lower() in MEMORY_OOM_KILL_OPTIONS:
                self.memory_oom_kill = memory_node["memory_oom_kill"].lower()
            else:
                raise ExtensionHandlerConfigurationError("Malformed memory_oom_kill flag in HandlerConfiguration")

    def __str__(self):
        return {"max_limit_MBs": self.max_limit_MBs,
                "max_limit_percentage": self.max_limit_percentage,
                "memory_oom_kill": self.memory_oom_kill,
                "memory_pressure_warning": self.memory_pressure_warning}.__str__()

    def __repr__(self):
        return {"max_limit_MBs": self.max_limit_MBs,
                "max_limit_percentage": self.max_limit_percentage,
                "memory_oom_kill": self.memory_oom_kill,
                "memory_pressure_warning": self.memory_pressure_warning}.__str__()


class CGroupsLimits(object):
    def __init__(self, cgroup_name, resource_configuration=None):
        self.osutil = get_osutil()

        if not cgroup_name or cgroup_name == "":
            cgroup_name = "Agents+Extensions"

        self.cpu_limit = self._get_cpu_limits(cgroup_name, resource_configuration,
                                              CGroupsLimits.get_default_cpu_limits)
        self.memory_limit = self._get_memory_limits(cgroup_name, resource_configuration,
                                                    CGroupsLimits.get_default_memory_limits)
        self.memory_flags = self._get_memory_flags(cgroup_name, resource_configuration,
                                                   CGroupsLimits.get_default_memory_flags)

    def _get_cpu_limits(self, cgroup_name, resource_configuration, compute_default):
        limit_requested = None

        # Refer azurelinuxagent.ga.utils.exthandler_utils.CpuLimits for the structure of requested limits
        cpu_limits_requested_by_extn = resource_configuration.get_cpu_limits_for_extension() if resource_configuration \
            else None

        if cpu_limits_requested_by_extn:
            cores_count = self.osutil.get_processor_cores()
            # Sorted by cores. -1 is the default entry - and the first entry.
            # Sorted inside azurelinuxagent.ga.exthandlers.CpuLimits

            default_limits = cpu_limits_requested_by_extn.cpu_limits[0]
            if len(cpu_limits_requested_by_extn.cpu_limits) > 1:
                for i in cpu_limits_requested_by_extn.cpu_limits[1:]:
                    if cores_count <= i.cores:
                        limit_requested = i.limit_percentage
                        break

            if not limit_requested:
                limit_requested = default_limits.limit_percentage

        return limit_requested if limit_requested else compute_default(cgroup_name)

    def _get_memory_limits(self, cgroup_name, resource_configuration, compute_default):
        limit_requested = None

        # Refer azurelinuxagent.ga.utils.exthandler_utils.MemoryLimits for the structure of requested limits
        memory_limits_requested_by_extn = resource_configuration.get_memory_limits_for_extension() if \
            resource_configuration else None

        if memory_limits_requested_by_extn:
            total_memory = self.osutil.get_total_mem()
            limit_requested = max(DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN,
                                  min((memory_limits_requested_by_extn.max_limit_percentage / 100.0) * total_memory,
                                      memory_limits_requested_by_extn.max_limit_MBs)
                                  )

        return limit_requested if limit_requested else compute_default(cgroup_name)

    def _get_memory_flags(self, cgroup_name, resource_configuration, compute_default):
        flags_requested = {}

        memory_limits_requested_by_extn = resource_configuration.get_memory_limits_for_extension() if \
            resource_configuration else None

        if memory_limits_requested_by_extn:
            if memory_limits_requested_by_extn.memory_pressure_warning:
                flags_requested["memory_pressure_warning"] = memory_limits_requested_by_extn.memory_pressure_warning
            else:
                flags_requested["memory_pressure_warning"] = compute_default(cgroup_name)["memory_pressure_warning"]

            if memory_limits_requested_by_extn.memory_oom_kill:
                flags_requested["memory_oom_kill"] = memory_limits_requested_by_extn.memory_oom_kill
            else:
                flags_requested["memory_oom_kill"] = compute_default(cgroup_name)["memory_oom_kill"]

        return flags_requested if bool(flags_requested) else compute_default(cgroup_name)

    @staticmethod
    def get_default_cpu_limits(cgroup_name):
        # default values
        cpu_limit = DEFAULT_CPU_LIMIT_EXT
        if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
            cpu_limit = DEFAULT_CPU_LIMIT_AGENT
        return cpu_limit

    @staticmethod
    def get_default_memory_limits(cgroup_name):
        os_util = get_osutil()

        # default values
        mem_limit = max(DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN, round(os_util.get_total_mem() * DEFAULT_MEM_LIMIT_PCT_FOR_EXTN / 100, 0))

        # agent values
        if AGENT_CGROUP_NAME.lower() in cgroup_name.lower():
            mem_limit = min(DEFAULT_MEM_LIMIT_MAX_MB_FOR_AGENT, mem_limit)
        return mem_limit

    @staticmethod
    def get_default_memory_flags(cgroup_name=None):
        default_memory_flags = {"memory_pressure_warning": None, "memory_oom_kill": "disabled"}
        return default_memory_flags

    def __str__(self):
        return {"cpu_limit": self.cpu_limit,
                "memory_limit": self.memory_limit,
                "memory_flags": self.memory_flags}.__str__()

    def __repr__(self):
        return {"cpu_limit": self.cpu_limit,
                "memory_limit": self.memory_limit,
                "memory_flags": self.memory_flags}.__str__()
