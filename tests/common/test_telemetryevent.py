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
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, GuestAgentExtensionEventsSchema, \
    CommonTelemetryEventSchema
from tests.tools import AgentTestCase


def get_test_event(name="DummyExtension", op="Unknown", is_success=True, duration=0, version="foo", evt_type="", is_internal=False, # pylint: disable=invalid-name,too-many-arguments
                      message="DummyMessage", eventId=1):
    event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Name, name))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Version, str(version)))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.IsInternal, is_internal))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Operation, op))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.OperationSuccess, is_success))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Message, message))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Duration, duration))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.ExtensionType, evt_type))
    return event


class TestTelemetryEvent(AgentTestCase):
    def test_contains_works_for_TelemetryEvent(self): # pylint: disable=invalid-name
        test_event = get_test_event(message="Dummy Event")

        self.assertTrue(GuestAgentExtensionEventsSchema.Name in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.Version in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.IsInternal in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.Operation in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.OperationSuccess in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.Message in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.Duration in test_event)
        self.assertTrue(GuestAgentExtensionEventsSchema.ExtensionType in test_event)

        self.assertFalse(CommonTelemetryEventSchema.GAVersion in test_event)
        self.assertFalse(CommonTelemetryEventSchema.ContainerId in test_event)