# Compose Content for: L1-conceptual/extension-goal-state-factory.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.EmptyExtensionsGoalState`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_extensions_config.py.ExtensionsGoalStateFromExtensionsConfig`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py.ExtensionsGoalStateFromVmSettings`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_empty`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_empty.incarnation`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_extensions_config`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_extensions_config.incarnation`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_extensions_config.xml_text`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_extensions_config.wire_client`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_vm_settings`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_factory.py.ExtensionsGoalStateFactory.create_from_vm_s

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

from azurelinuxagent.common.protocol.extensions_goal_state import EmptyExtensionsGoalState
from azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config import ExtensionsGoalStateFromExtensionsConfig
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import ExtensionsGoalStateFromVmSettings


class ExtensionsGoalStateFactory(object):
    @staticmethod
    def create_empty(incarnation):
        return EmptyExtensionsGoalState(incarnation)

    @staticmethod
    def create_from_extensions_config(incarnation, xml_text, wire_client):
        return ExtensionsGoalStateFromExtensionsConfig(incarnation, xml_text, wire_client)

    @staticmethod
    def create_from_vm_settings(etag, json_text, correlation_id):
        return ExtensionsGoalStateFromVmSettings(etag, json_text, correlation_id)


````

---
