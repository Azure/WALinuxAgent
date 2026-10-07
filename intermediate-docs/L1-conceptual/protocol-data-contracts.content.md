# Compose Content for: L1-conceptual/protocol-data-contracts.md

Total files: 2

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/datacontract.py.DataContract`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VERSION_0`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.subscriptionId`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.vmName`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.roleName`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.roleInstanceName`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMInfo.__init__.tenantName`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily.__init__`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily.__init__.name`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily.__repr__`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamil

### Source excerpt

````
# Microsoft Azure Linux Agent
#
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
#

import socket
import time

from azurelinuxagent.common.datacontract import DataContract, DataContractList
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.textutil import getattrib
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME, CURRENT_VERSION


VERSION_0 = "0.0.0.0"


class VMInfo(DataContract):
    def __init__(self,
                 subscriptionId=None,
                 vmName=None,
                 roleName=None,
                 roleInstanceName=None,
                 tenantName=None):
        self.subscriptionId = subscriptionId
        self.vmName = vmName
        self.roleName = roleName
        self.roleInstanceName = roleInstanceName
        self.tenantName = tenantName


class VMAgentFamily(object):
    def __init__(self, name):
        self.name = name
        # Two-state: None, string. Set to None if version not specified in the GS
        self.version = None
        # Two-state: None, string. Set to None if this property not specified in the GS.
        self.from_version = None
        # Tri-state: None, True, False. Set to None if this property not specified in the GS.
        self.is_version_from_rsm = None
        # Tri-state: None, True, False. Set to None if this property not specified in the GS.
        self.is_vm_enabled_for_rsm_upgrades = None
        # One-state: dict. Empty dict if no mapping specified in the GS.
        self.ga_version_to_signature_mapping = {}

        self.uris = []

    def __repr__(self):
        return self.__s
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/datacontract.py.DataContract`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.EventPid`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.EventTid`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.GAVersion`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.ContainerId`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.TaskName`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.OpcodeName`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.KeywordName`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.OSVersion`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.ExecutionMode`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.RAM`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.Processors`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.TenantName`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema.RoleName`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema

### Source excerpt

````
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


class CommonTelemetryEventSchema(object):

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


class GuestAgentGenericLogsSchema(CommonTelemetryEventSchema):

    # GuestAgentGenericLogs table specific schema keys
    EventName = "EventName"
    CapabilityUsed = "CapabilityUsed"
    Context1 = "Context1"
    Context2 = "Context2"
    Context3 = "Context3"


class GuestAgentExtensionEventsSchema(CommonTelemetryEventSchema):

    # GuestAgentExtensionEvents table specific schema keys
    ExtensionType = "ExtensionType"
    IsInternal = "IsInternal"
    Name = "Name"
    Version = "Version"
    Operation = "Operation"
    OperationSuccess = "OperationSuccess"
    Message = "Message"
    Duration = "Duration"


class GuestAgentPerfCounterEve
````

---
