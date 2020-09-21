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

import uuid
from mock import MagicMock, Mock

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.telemetryevent import TelemetryEvent
from azurelinuxagent.ga.telemetry_service import get_telemetry_service_handler
from tests.protocol.mocks import MockHttpResponse, mock_wire_protocol
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import AgentTestCase, clear_singleton_instances


class TestExtensionTelemetryHandler(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        clear_singleton_instances(ProtocolUtil)

    @contextlib.contextmanager
    def _create_telemetry_service_handler(self):
        def http_post_handler(url, body, **__):
            if self.is_telemetry_request(url):
                telemetry_service_handler.event_body.append(body)
                return MockHttpResponse(status=200)
            return None

        with mock_wire_protocol(DATA_FILE, http_post_handler=http_post_handler) as protocol:
            protocol_util = MagicMock()
            protocol_util.get_protocol = Mock(return_value=protocol)
            telemetry_service_handler = get_telemetry_service_handler(protocol_util)
            telemetry_service_handler.event_body = []
            telemetry_service_handler.start()
            yield telemetry_service_handler

    def test_it_should_send_events_properly(self):
        raise NotImplementedError
        test_guid = ustr(uuid.uuid4())
        events = [TelemetryEvent(eventId=test_guid), TelemetryEvent(providerId=test_guid)]

        with self._create_telemetry_service_handler() as telemetry_handler:
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)




    def test_it_should_send_as_soon_as_events_available_in_queue(self):
        raise NotImplementedError

    def test_thread_should_wait_for_events_in_queue(self):
        raise NotImplementedError

    def test_it_should_honour_the_priority_order_of_events(self):
        raise NotImplementedError

    def test_it_should_try_sending_events_periodically(self):
        raise NotImplementedError

    def test_it_should_send_events(self):
        raise NotImplementedError