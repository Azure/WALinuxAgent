# Compose Content for: L1-conceptual/goal-state-domain-models.md

Total files: 5

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals`
- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals.GUID_ZERO`
- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals._container_id`
- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals.get_container_id`
- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals.update_container_id`
- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals.update_container_id.container_id`

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


class AgentGlobals(object):
    """
    This class is used for setting AgentGlobals which can be used all throughout the Agent.
    """

    GUID_ZERO = "00000000-0000-0000-0000-000000000000"

    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    _container_id = GUID_ZERO

    #
    # The telemetry modules require the information about whether the agent is running in a CVM or not. This variable
    # will be updated when the CVM info is initialized in ConfidentialVMInfo. There are three possible values:
    #   - None
    #   - True
    #   - False
    # The value is None when the CVM info has not yet been initialized.
    #
    _is_cvm = None

    @staticmethod
    def get_container_id():
        return AgentGlobals._container_id

    @staticmethod
    def update_container_id(container_id):
        AgentGlobals._container_id = container_id

    @staticmethod
    def get_is_cvm():
        # The value of _is_cvm is uninitialized until ConfidentialVMInfo.fetch_and_initialize_cvm_info() is called. The value
        # is only initialized on the ExtHandler process, since fetching the CVM info requires an extra network call and the value
        # is not needed on the Daemon or LogCollector processes.
        # If this method is called before the value is initialized, raise an exception.
        if AgentGlobals._is_cvm is None:
            raise Exception("CVM info has not been initialized yet")
        return AgentGloba
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals`
- `%REPO%/azurelinuxagent/common/exception.py.EventError`
- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/datacontract.py.get_properties`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.TelemetryEventParam`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.TelemetryEvent`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.CommonTelemetryEventSchema`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.GuestAgentGenericLogsSchema`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.GuestAgentExtensionEventsSchema`
- `%REPO%/azurelinuxagent/common/telemetryevent.py.GuestAgentPerfCounterEventsSchema`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.str_to_encoded_ustr`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.redact_sas_token`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_AGENT`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.

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

import atexit
import json
import os
import platform
import re
import sys
import threading
import time
import traceback
from datetime import datetime

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import EventError, OSUtilError
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.telemetryevent import TelemetryEventParam, TelemetryEvent, CommonTelemetryEventSchema, \
    GuestAgentGenericLogsSchema, GuestAgentExtensionEventsSchema, GuestAgentPerfCounterEventsSchema
from azurelinuxagent.common.utils import fileutil, textutil, timeutil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, getattrib, str_to_encoded_ustr, \
    redact_sas_token
from azurelinuxagent.common.version import CURRENT_VERSION, CURRENT_AGENT, AGENT_NAME, DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, AGENT_EXECUTION_MODE
from azurelinuxagent.common.protocol.imds import get_imds_client

EVENTS_DIRECTORY = "events"

_EVENT_MSG = "Event: name={0}, op={1}, message={2}, duration={3}"
TELEMETRY_EVENT_PROVIDER_ID = "69B669B9-4AF8-4C50-BDC4-6006FA76E975"
TELEMETRY_EVENT_EVENT_ID = 1
TELEMETRY_METRICS_EVENT_ID = 4

TELEMETRY_LOG_PROVIDER_ID = "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F"
TELEMETRY_LOG_EVENT_ID = 7

#
# When this flag is enabled the TODO comment in Logger.log() needs to be addressed; also the tests
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel.WireServer`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel.HostGAPlugin`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel.Empty`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource.Fabric`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource.FastTrack`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource.Empty`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError.__init__`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError.__init__.message`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError.__init__.etag`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError.__

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
import datetime

from azurelinuxagent.common import logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.future import datetime_min_utc
from azurelinuxagent.common.utils import textutil, timeutil


class GoalStateChannel(object):
    WireServer = "WireServer"
    HostGAPlugin = "HostGAPlugin"
    Empty = "Empty"


class GoalStateSource(object):
    Fabric = "Fabric"
    FastTrack = "FastTrack"
    Empty = "Empty"


class VmSettingsParseError(AgentError):
    """
    Error raised when the VmSettings are malformed
    """
    def __init__(self, message, etag, vm_settings_text, inner=None):
        super(VmSettingsParseError, self).__init__(message, inner)
        self.etag = etag
        self.vm_settings_text = vm_settings_text


class ExtensionsGoalState(object):
    """
    ExtensionsGoalState represents the extensions information in the goal state; that information can originate from
    ExtensionsConfig when the goal state is retrieved from the WireServe or from vmSettings when it is retrieved from
    the HostGAPlugin.

    NOTE: This is an abstract class. The corresponding concrete classes can be instantiated using the ExtensionsGoalStateFactory.
    """
    def __init__(self):
        self._is_outdated = False

    @property
    def id(self):
        """
        Returns a string that includes the incarnation number if the ExtensionsGoalState was created from ExtensionsConfig, or the etag if it
        was created
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.ExtensionsGoalState`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.Extension`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtensionRequestedState`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtensionSettings`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py._MIN_HGAP_VERSION_FOR_EXT_SIGNATURE`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py.ExtensionsGoalStateFromVmSettings`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py.ExtensionsGoalStateFromVmSettings.__init__`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py.ExtensionsGoalStateFromVmSettings.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py.ExtensionsGoalStateFromVmSettings.__init__.etag`
- `%REP

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
import json
import sys

from azurelinuxagent.common import logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.future import ustr, urlparse, datetime_min_utc
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateChannel, VmSettingsParseError
from azurelinuxagent.common.protocol.restapi import VMAgentFamily, Extension, ExtensionRequestedState, ExtensionSettings
from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo

# The 'encodedSignature' property is only supported on newer versions of HGAP.
_MIN_HGAP_VERSION_FOR_EXT_SIGNATURE = FlexibleVersion("1.0.8.159")

# The 'versionToSignatureMappings' property in the Agent Family is only supported on newer versions of HGAP.
_MIN_HGAP_VERSION_FOR_AGENT_SIGNATURE_MAPPING = FlexibleVersion("1.0.8.177")

class ExtensionsGoalStateFromVmSettings(ExtensionsGoalState):
    def __init__(self, etag, json_text, correlation_id):
        super(ExtensionsGoalStateFromVmSettings, self).__init__()
        self._id = "etag_{0}".format(etag)
        self._etag = etag
        self._svd_sequence_number = 0
        self._hostga_plugin_correlation_id = correlation_id
        self._text = json_text
        self._host_ga_plugin_version = FlexibleVersion('0.0.0.0')
        self._schema_version = FlexibleVer
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/AgentGlobals.py.AgentGlobals`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.LogEvent`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceGoneError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.VmSettingsNotSupported`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.VmSettingsSupportStopped`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.RemoteAccessUser`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.RemoteAccessUsersList`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtHandlerPackage`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtHandlerPackageList`
- `%REPO%/azurelinuxagent/common/utils/archive.py.GoalStateHistory`
- `%REPO%/azurelinuxagent/common/utils/archive.py.SHARED_CONF_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/co

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
import datetime
import os
import re
import time
import json

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.event import add_event, WALAEventOperation, LogEvent
from azurelinuxagent.common.exception import ProtocolError, ResourceGoneError
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.hostplugin import VmSettingsNotSupported, VmSettingsSupportStopped
from azurelinuxagent.common.protocol.restapi import RemoteAccessUser, RemoteAccessUsersList, ExtHandlerPackage, ExtHandlerPackageList
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.archive import GoalStateHistory, SHARED_CONF_FILE_NAME
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext
from azurelinuxagent.ga.signature_validation_util import ext_signature_validation_enabled


GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PFX_FILE_NAME = "Certificates.pfx"
PEM_FILE_NAME = "Certificates.pem"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "Trans
````

---
