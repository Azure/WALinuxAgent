# Compose Content for: L2-platform/service-error-state.md

Total files: 4

---

## setup.py

### Structural symbols

N/A

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


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/errorstate.py.ERROR_STATE_DELTA_DEFAULT`
- `%REPO%/azurelinuxagent/common/errorstate.py.ERROR_STATE_DELTA_INSTALL`
- `%REPO%/azurelinuxagent/common/errorstate.py.ERROR_STATE_HOST_PLUGIN_FAILURE`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.__init__`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.__init__.self`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.__init__.min_timedelta`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.incr`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.incr.self`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.reset`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.reset.self`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.is_triggered`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.is_triggered.self`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.fail_time`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState.fail_time.self`

### Source excerpt

````
from datetime import datetime, timedelta
from azurelinuxagent.common.future import UTC

ERROR_STATE_DELTA_DEFAULT = timedelta(minutes=15)
ERROR_STATE_DELTA_INSTALL = timedelta(minutes=5)
ERROR_STATE_HOST_PLUGIN_FAILURE = timedelta(minutes=5)


class ErrorState(object):
    def __init__(self, min_timedelta=ERROR_STATE_DELTA_DEFAULT):
        self.min_timedelta = min_timedelta

        self.count = 0
        self.timestamp = None

    def incr(self):
        if self.count == 0:
            self.timestamp = datetime.now(UTC)

        self.count += 1

    def reset(self):
        self.count = 0
        self.timestamp = None

    def is_triggered(self):
        if self.timestamp is None:
            return False

        delta = datetime.now(UTC) - self.timestamp
        if delta >= self.min_timedelta:
            return True

        return False

    @property
    def fail_time(self):
        if self.timestamp is None:
            return 'unknown'

        delta = round((datetime.now(UTC) - self.timestamp).seconds / 60.0, 2)
        if delta < 60:
            return '{0} min'.format(delta)

        delta_hr = round(delta / 60.0, 2)
        return '{0} hr'.format(delta_hr)

````

---

## setup.py

### Structural symbols

N/A

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

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState`
- `%REPO%/azurelinuxagent/common/errorstate.py.ERROR_STATE_HOST_PLUGIN_FAILURE`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/exception.py.HttpError`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceGoneError`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.VmSettingsParseError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.remove_bom`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MAJOR`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.HOST_PLUGIN_PORT`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.URI_FORMAT_GET_API_VERSIONS`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.URI_FORMAT_VM_SETTINGS`
- `%REPO%/azurelinuxagent/common/protocol/hostplugin.py.URI_FORMAT_GET_EXTENSION_ARTIFACT`
- `%RE

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
import base64
import datetime
import json
import os.path
import threading
import uuid

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.errorstate import ErrorState, ERROR_STATE_HOST_PLUGIN_FAILURE
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import HttpError, ProtocolError, ResourceGoneError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, httpclient, UTC, datetime_min_utc
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.utils import restutil, textutil, timeutil
from azurelinuxagent.common.utils.textutil import remove_bom
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, PY_VERSION_MAJOR

HOST_PLUGIN_PORT = 32526

URI_FORMAT_GET_API_VERSIONS = "http://{0}:{1}/versions"
URI_FORMAT_VM_SETTINGS = "http://{0}:{1}/vmSettings"
URI_FORMAT_GET_EXTENSION_ARTIFACT = "http://{0}:{1}/extensionArtifact"
URI_FORMAT_PUT_VM_STATUS = "http://{0}:{1}/status"
URI_FORMAT_PUT_LOG = "http://{0}:{1}/vmAgentLog"
URI_FORMAT_HEALTH = "http://{0}:{1}/health"

API_VERSION = "2015-09-01"

_HEADER_CLIENT_NAME = "x-ms-client-name"
_HEADER_CLIENT_VERSION = "x-ms-client-version"
_HEADER_CORRELATION_ID = "x-ms-clie
````

---
