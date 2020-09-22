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
import contextlib
import re
import time
import uuid
from datetime import datetime, timedelta

from mock import MagicMock, Mock, patch

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import event_to_v1_encoded
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventPriorities, TelemetryEventParam
from azurelinuxagent.ga.telemetry_service import get_telemetry_service_handler
from tests.protocol.mocks import MockHttpResponse, mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import AgentTestCase, clear_singleton_instances


class TestExtensionTelemetryHandler(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        clear_singleton_instances(ProtocolUtil)

    @contextlib.contextmanager
    def _create_telemetry_service_handler(self, timeout=0.5, start_thread=True):
        def http_post_handler(url, body, **__):
            if self.is_telemetry_request(url):
                telemetry_service_handler.event_calls.append((datetime.now(), body))
                return MockHttpResponse(status=200)
            return None

        with mock_wire_protocol(DATA_FILE, http_post_handler=http_post_handler) as protocol:
            protocol_util = MagicMock()
            protocol_util.get_protocol = Mock(return_value=protocol)
            telemetry_service_handler = get_telemetry_service_handler(protocol_util)
            telemetry_service_handler.event_calls = []
            with patch("azurelinuxagent.ga.telemetry_service.TelemetryServiceHandler._MAX_TIMEOUT", timeout):
                if start_thread:
                    telemetry_service_handler.start()
                    self.assertTrue(telemetry_service_handler.is_alive(), "Thread didn't start properly!")
                yield telemetry_service_handler

    def _assert_test_data_in_event_body(self, telemetry_handler, test_events):
        # Stop the thread and Wait for the queue and thread to join
        telemetry_handler.stop()

        for event in test_events:
            event_str = event_to_v1_encoded(event)
            found = False
            for _, event_body in telemetry_handler.event_calls:
                if event_str in event_body:
                    found = True
                    break

            self.assertTrue(found, "Event {0} not found in any telemetry calls".format(event_str))

    def test_it_should_send_events_properly(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]

        with self._create_telemetry_service_handler() as telemetry_handler:
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_send_as_soon_as_events_available_in_queue(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]

        with self._create_telemetry_service_handler() as telemetry_handler:
            test_start_time = datetime.now()
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

            # Ensure that we send out the data as soon as we enqueue the events
            for event_time, _ in telemetry_handler.event_calls:
                elapsed = event_time - test_start_time
                self.assertLessEqual(elapsed, timedelta(seconds=2), "Request was not sent as soon as possible")

    def test_thread_should_wait_for_events_to_get_in_queue_before_processing(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]

        with self._create_telemetry_service_handler(timeout=0.1) as telemetry_handler:

            # Do nothing for some time
            time.sleep(0.3)

            # Ensure that no events were transmitted by the telemetry handler during this time, i.e. telemetry thread was idle
            self.assertEqual(0, len(telemetry_handler.event_calls), "Unwanted calls to telemetry")

            # Now enqueue data and verify telemetry_service sends them asap
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_honour_the_priority_order_of_events(self):

        # In general, lower the number, higher the priority
        # Priority Order: AGENT_EVENT > EXTENSION_EVENT_NEW_PIPELINE > EXTENSION_EVENT_OLD_PIPELINE
        events = [
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.EXTENSION_EVENT_OLD_PIPELINE),
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.EXTENSION_EVENT_OLD_PIPELINE),
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.AGENT_EVENT),
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.EXTENSION_EVENT_NEW_PIPELINE),
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.EXTENSION_EVENT_NEW_PIPELINE),
            TelemetryEvent(eventId=ustr(uuid.uuid4()), priority=TelemetryEventPriorities.AGENT_EVENT)
        ]
        expected_priority_order = []

        with self._create_telemetry_service_handler(timeout=0.3, start_thread=False) as telemetry_handler:
            for test_event in events:
                test_event.parameters.append(TelemetryEventParam("Priority", test_event.priority))
                expected_priority_order.append(str(test_event.priority))
                telemetry_handler.enqueue_event(test_event)

            telemetry_handler.start()
            # Give the thread some time to start up, this was causing concurrency issues in UTs
            time.sleep(0.005)
            self.assertTrue(telemetry_handler.is_alive(), "Thread not alive")
            self._assert_test_data_in_event_body(telemetry_handler, events)

            priorities = []
            regex_pattern = r'<Param Name="Priority" Value="(\d+)" T="mt:uint64" />'
            for _, event_body in telemetry_handler.event_calls:
                priorities.extend(re.findall(regex_pattern, event_body))

            self.assertEqual(sorted(expected_priority_order), priorities, "Priorities dont match")