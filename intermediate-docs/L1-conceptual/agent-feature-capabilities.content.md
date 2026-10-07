# Compose Content for: L1-conceptual/agent-feature-capabilities.md

Total files: 5

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames.MultiConfig`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames.ExtensionTelemetryPipeline`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames.FastTrack`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames.GAVersioningGovernance`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.__init__`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.__init__.self`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.__init__.name`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.__init__.version`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.__init__.supported`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.name`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.name.self`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.version`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupportedFeature.version.self`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.AgentSupported

### Source excerpt

````
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
from azurelinuxagent.common import conf


class SupportedFeatureNames(object):
    """
    Enum for defining the Feature Names for all features that we the agent supports
    """
    MultiConfig = "MultipleExtensionsPerHandler"
    ExtensionTelemetryPipeline = "ExtensionTelemetryPipeline"
    FastTrack = "FastTrack"
    GAVersioningGovernance = "VersioningGovernance"  # Guest Agent Versioning


class AgentSupportedFeature(object):
    """
    Interface for defining all features that the Linux Guest Agent supports and reports their if supported back to CRP
    """

    def __init__(self, name, version="1.0", supported=False):
        self.__name = name
        self.__version = version
        self.__supported = supported

    @property
    def name(self):
        return self.__name

    @property
    def version(self):
        return self.__version

    @property
    def is_supported(self):
        return self.__supported


class _MultiConfigFeature(AgentSupportedFeature):

    __NAME = SupportedFeatureNames.MultiConfig
    __VERSION = "1.0"
    __SUPPORTED = True

    def __init__(self):
        super(_MultiConfigFeature, self).__init__(name=_MultiConfigFeature.__NAME,
                                                  version=_MultiConfigFeature.__VERSION,
                                                  supported=_MultiConfigFeature.__SUPPORTED)


class _ETPFeature(AgentSupportedFeature):

    __NAME = SupportedFeatureNames.ExtensionTelemetryPipeline
    __VERSION = "1.0"
    __SUPPORTED = True

    def __init__(self):
        super(_ETPFeatur
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_agent_supported_features_list_for_crp`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames`
- `%REPO%/azurelinuxagent/common/datacontract.py.validate_param`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.report_event`
- `%REPO%/azurelinuxagent/common/event.py.CollectOrReportEventDebugInfo`
- `%REPO%/azurelinuxagent/common/event.py.add_periodic`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolNotFoundError`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceGoneError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionDownloadError`
- `%REPO%/azurelinuxagent/common/exception.py.InvalidContainerError`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/exception.py.HttpError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionErrorCodes`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.GoalState`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.TRANSPORT_CERT_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.TRANSPORT_PRV_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.GoalStateProperties`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.HostPluginProtocol`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContract`
- `%REPO%/azurelinuxagent/common/protocol/res

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

import json
import os
import random
import shutil
import time
import zipfile

from collections import defaultdict
from datetime import datetime, timedelta
from xml.sax import saxutils

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_crp, SupportedFeatureNames
from azurelinuxagent.common.datacontract import validate_param
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_event, \
    CollectOrReportEventDebugInfo, add_periodic
from azurelinuxagent.common.exception import ProtocolNotFoundError, \
    ResourceGoneError, ExtensionDownloadError, InvalidContainerError, ProtocolError, HttpError, ExtensionErrorCodes
from azurelinuxagent.common.future import httpclient, bytebuffer, ustr, UTC
from azurelinuxagent.common.protocol.goal_state import GoalState, TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME, GoalStateProperties
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import DataContract, ProvisionStatus, VMInfo, VMStatus
from azurelinuxagent.common.telemetryevent import GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.restutil import TELEMETRY_THROTTLE_DELAY_IN_SECONDS, \
    TELEMETRY_FLUSH_THROTTLE_DELAY_
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_supported_feature_by_name`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames`
- `%REPO%/azurelinuxagent/common/event.py.EVENTS_DIRECTORY`
- `%REPO%/azurelinuxagent/common/event.py.TELEMETRY_LOG_EVENT_ID`
- `%REPO%/azurelinuxagent/common/event.py.TELEMETRY_LOG_PROVIDER_ID`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_log_event`
- `%REPO%/azurelinuxagent/common/event.py.get_event_logger`
- `%REPO%/azurelinuxagent/common/event.py.CollectOrReportEventDebugInfo`
- `%REPO%/azurelinuxagent/common/event.py.EVENT_FILE_REGEX`
- `%REPO%/azurelinuxagent/common/event.py.parse_event`
- `%REPO%/azurelinuxagent/common/event.py.redact_event_msg`
- `%REPO%/azurelinuxagent/common/exception.py.InvalidExtensionEventError`
- `%REPO%/azurelinuxagent/common/exception.py.ServiceStoppedError`
- `%REPO%/azurelinuxagent/common/exception.py.EventError`
- `%REPO%/azurelinuxagent/common/future.py.is_file_not_found_error`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.redact_sas_token`
- `%REPO%/azurelinuxagent/ga/interfaces.py.ThreadHandlerInterface`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.TelemetryEvent`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.TelemetryEventParam`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.GuestAgentGenericLogsSchema`
- `%REPO%/azurelinuxagent/com

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
import datetime
import json
import os
import re
import threading
import time
from collections import defaultdict

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common import conf
from azurelinuxagent.common.agent_supported_feature import get_supported_feature_by_name, SupportedFeatureNames
from azurelinuxagent.common.event import EVENTS_DIRECTORY, TELEMETRY_LOG_EVENT_ID, \
    TELEMETRY_LOG_PROVIDER_ID, add_event, WALAEventOperation, add_log_event, get_event_logger, \
    CollectOrReportEventDebugInfo, EVENT_FILE_REGEX, parse_event, redact_event_msg
from azurelinuxagent.common.exception import InvalidExtensionEventError, ServiceStoppedError, EventError
from azurelinuxagent.common.future import ustr, is_file_not_found_error, UTC
from azurelinuxagent.common.utils.textutil import redact_sas_token
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, \
    GuestAgentGenericLogsSchema, GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.ga.exthandlers import HANDLER_NAME_PATTERN
from azurelinuxagent.ga.periodic_operation import PeriodicOperation

# Event file specific retries and delays.
NUM_OF_EVENT_FILE_RETRIES = 3
EVENT_FILE_RETRY_DELAY = 1  # seconds


def get_collect_telemetry_events_handler(send_telemetry_events_handler):
    return CollectTelemetryEventsHandler(send_telemetry_events_handler)


class ExtensionEventSchema(object):
    """
    Cla
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_agent_supported_features_list_for_extensions`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_supported_feature_by_name`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_agent_supported_features_list_for_crp`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.redact_sas_token`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.CGroupConfigurator`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.ExtensionPolicyEngine`
- `%REPO%/azurelinuxagent/common/datacontract.py.get_properties`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.elapsed_milliseconds`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_periodic`
- `%REPO%/azurelinuxagent/common/event.py.EVENTS_DIRECTORY`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionDownloadError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionErrorCodes`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionOperationError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionUpdateError`
- `%REPO%/az

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
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
import copy
import datetime
import glob
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from collections import defaultdict
from functools import partial

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common import version
from azurelinuxagent.common import event
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_extensions, \
    SupportedFeatureNames, get_supported_feature_by_name, get_agent_supported_features_list_for_crp
from azurelinuxagent.common.utils.textutil import redact_sas_token
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine, ExtensionDisallowedError, \
    ExtensionSignaturePolicyError, ExtensionUnsignedError, ExtensionSignatureNotValidatedError
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, elapsed_milliseconds, WALAEventOperation, \
    add_periodic, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ExtensionDownloadError, ExtensionError, ExtensionErrorCodes, \
    ExtensionOperationError, ExtensionUpdateError, ProtocolError, ProtocolNotFoundError, ExtensionsGoalStateError, \
    GoalStateAggreg
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_supported_feature_by_name`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.SupportedFeatureNames`
- `%REPO%/azurelinuxagent/common/agent_supported_feature.py.get_agent_supported_features_list_for_crp`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.KNOWN_WIRESERVER_IP`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.CGroupConfigurator`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.initialize_event_logger_vminfo_common_parameters_and_protocol`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.EVENTS_DIRECTORY`
- `%REPO%/azurelinuxagent/common/exception.py.ExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpgradeExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallStateError`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.HostPluginProtocol`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.VmSettingsNotSupported`
- `%REP

### Source excerpt

````

# Windows Azure Linux Agent
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
import glob
import errno
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.agent_supported_feature import get_supported_feature_by_name, SupportedFeatureNames, \
    get_agent_supported_features_list_for_crp
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.event import add_event, initialize_event_logger_vminfo_common_parameters_and_protocol, \
    WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ExitException, AgentUpgradeExitException, AgentMemoryExceededException
from azurelinuxagent.ga.firewall_manager import FirewallManager, FirewallStateError, IptablesInconsistencyError
from azurelinuxagent.common.future import ustr, UTC, datetime_min_utc
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.ga.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.goal_state import GoalStateSource, TRANSPORT_CERT_FILE_NAME
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol, VmSettingsNotSupported
from azurelinuxagent.common.protocol.restapi import VERSION_0
from
````

---
