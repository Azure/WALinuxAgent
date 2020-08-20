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
#

from azurelinuxagent.common.datacontract import DataContract, DataContractList
from azurelinuxagent.common.version import AGENT_NAME

class CommonTelemetryEventSchema(object): # pylint: disable=R0903

    # Common schema keys for GuestAgentExtensionEvents, GuestAgentGenericLogs
    # and GuestAgentPerformanceCounterEvents tables in Kusto.
    EventPid = "EventPid"
    EventTid = "EventTid"
    GAVersion = "GAVersion"
    ContainerId = "ContainerId"
    TaskName = "TaskName"
    OpcodeName = "OpcodeName"
    KeywordName = "KeywordName"
    OSVersion = "OSVersion"
    ExecutionMode = "ExecutionMode"
    RAM = "RAM"
    Processors = "Processors"
    TenantName = "TenantName"
    RoleName = "RoleName"
    RoleInstanceName = "RoleInstanceName"
    Location = "Location"
    SubscriptionId = "SubscriptionId"
    ResourceGroupName = "ResourceGroupName"
    VMId = "VMId"
    ImageOrigin = "ImageOrigin"

class GuestAgentGenericLogsSchema(CommonTelemetryEventSchema): # pylint: disable=R0903

    # GuestAgentGenericLogs table specific schema keys
    EventName = "EventName"
    CapabilityUsed = "CapabilityUsed"
    Context1 = "Context1"
    Context2 = "Context2"
    Context3 = "Context3"

class GuestAgentExtensionEventsSchema(CommonTelemetryEventSchema): # pylint: disable=R0903

    # GuestAgentExtensionEvents table specific schema keys
    ExtensionType = "ExtensionType"
    IsInternal = "IsInternal"
    Name = "Name"
    Version = "Version"
    Operation = "Operation"
    OperationSuccess = "OperationSuccess"
    Message = "Message"
    Duration = "Duration"

class GuestAgentPerfCounterEventsSchema(CommonTelemetryEventSchema): # pylint: disable=R0903

    # GuestAgentPerformanceCounterEvents table specific schema keys
    Category = "Category"
    Counter = "Counter"
    Instance = "Instance"
    Value = "Value"

class TelemetryEventParam(DataContract): # pylint: disable=R0903
    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value

    def __eq__(self, other):
        return isinstance(other, TelemetryEventParam) and other.name == self.name and other.value == self.value


class TelemetryEvent(DataContract):
    def __init__(self, eventId=None, providerId=None):
        self.eventId = eventId # pylint: disable=C0103
        self.providerId = providerId # pylint: disable=C0103
        self.parameters = DataContractList(TelemetryEventParam)
        self.file_type = ""

    # Checking if the particular param name is in the TelemetryEvent.
    def __contains__(self, param_name):
        return param_name in [param.name for param in self.parameters]

    def is_extension_event(self):
        # Events originating from the agent have "WALinuxAgent" as the Name parameter, or they don't have a Name
        # parameter, in the case of log and metric events. So, in case the Name parameter exists and it is not
        # "WALinuxAgent", it is an extension event.
        for param in self.parameters:
            if param.name == GuestAgentExtensionEventsSchema.Name:
                return param.value != AGENT_NAME
        return False

    def get_version(self):
        for param in self.parameters:
            if param.name == GuestAgentExtensionEventsSchema.Version:
                return param.value
        return None


class TelemetryEventList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.events = DataContractList(TelemetryEvent)
