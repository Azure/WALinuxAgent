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

import tempfile

import os

import json

import platform

from mock import MagicMock, Mock, patch, PropertyMock
from azurelinuxagent.common.osutil.factory import get_osutil

from azurelinuxagent.common import logger
from azurelinuxagent.common.datacontract import get_properties

from azurelinuxagent.common.utils import restutil, fileutil, textutil

from azurelinuxagent.common.event import WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import event_to_v1_encoded
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventPriorities, TelemetryEventParam, \
    GuestAgentExtensionEventsSchema
from azurelinuxagent.common.version import CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, AGENT_VERSION, CURRENT_AGENT, \
    DISTRO_CODE_NAME
from azurelinuxagent.ga.monitor import CollectAndEnqueueEventsPeriodicOperation
from azurelinuxagent.ga.telemetry_service import get_telemetry_service_handler
from tests.ga.test_monitor import random_generator
from tests.protocol.mocks import MockHttpResponse, mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import AgentTestCase, clear_singleton_instances
from tests.utils.event_logger_tools import EventLoggerTools


class TestTelemetryServiceHandler(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        clear_singleton_instances(ProtocolUtil)
        self.lib_dir = tempfile.mkdtemp()
        self.event_dir = os.path.join(self.lib_dir, EVENTS_DIRECTORY)

        EventLoggerTools.initialize_event_logger(self.event_dir)

    def tearDown(self):
        AgentTestCase.tearDown(self)
        fileutil.rm_dirs(self.lib_dir)

    _TEST_EVENT_PROVIDER_ID = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

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
                telemetry_service_handler.get_mock_wire_protocol = lambda: protocol
                if start_thread:
                    telemetry_service_handler.start()
                    self.assertTrue(telemetry_service_handler.is_alive(), "Thread didn't start properly!")
                yield telemetry_service_handler

    @staticmethod
    def _stop_handler(telemetry_handler, timeout=0.001):
        # Giving it some grace time to finish execution and then stopping thread
        time.sleep(timeout)
        telemetry_handler.stop()

    def _assert_test_data_in_event_body(self, telemetry_handler, test_events):
        # Stop the thread and Wait for the queue and thread to join
        TestTelemetryServiceHandler._stop_handler(telemetry_handler)

        for telemetry_event in test_events:
            event_str = event_to_v1_encoded(telemetry_event)
            found = False
            for _, event_body in telemetry_handler.event_calls:
                if event_str in event_body:
                    found = True
                    break

            self.assertTrue(found, "Event {0} not found in any telemetry calls".format(event_str))

    def _assert_error_event_reported(self, mock_add_event, expected_msg, operation=WALAEventOperation.ReportEventErrors):
        found_msg = False
        for call_args in mock_add_event.call_args_list:
            _, kwargs = call_args
            if expected_msg in kwargs['message'] and kwargs['op'] == operation:
                found_msg = True
                break
        self.assertTrue(found_msg, "Error msg: {0} not reported".format(expected_msg))

    def _setup_and_assert_bad_request_scenarios(self, http_post_handler, expected_msgs):
        with self._create_telemetry_service_handler() as telemetry_handler:

            telemetry_handler.get_mock_wire_protocol().set_http_handlers(http_post_handler=http_post_handler)

            with patch("azurelinuxagent.common.event.add_event") as mock_add_event:
                telemetry_handler.enqueue_event(TelemetryEvent())
                TestTelemetryServiceHandler._stop_handler(telemetry_handler)
                for msg in expected_msgs:
                    self._assert_error_event_reported(mock_add_event, msg)

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
                priorities.extend(re.findall(regex_pattern, textutil.str_to_encoded_ustr(event_body)))

            self.assertEqual(sorted(expected_priority_order), priorities, "Priorities dont match")

    def test_telemetry_service_with_call_wireserver_returns_http_error_and_reports_event(self):

        test_str = "A test exception, Guid: {0}".format(str(uuid.uuid4()))

        def http_post_handler(url, _, **__):
            if self.is_telemetry_request(url):
                return HttpError(test_str)
            return None

        self._setup_and_assert_bad_request_scenarios(http_post_handler, [test_str])

    def test_telemetry_service_should_report_event_when_http_post_returning_503(self):

        def http_post_handler(url, _, **__):
            if self.is_telemetry_request(url):
                return MockHttpResponse(restutil.httpclient.SERVICE_UNAVAILABLE)
            return None

        expected_msgs = ["[ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed]",
                        "[HTTP Failed] Status Code 503"]

        self._setup_and_assert_bad_request_scenarios(http_post_handler, expected_msgs)

    def test_telemetry_service_should_add_event_on_unexpected_errors(self):

        with self._create_telemetry_service_handler(timeout=0.1) as telemetry_handler:

            # This test validates that if we hit an issue while sending an event, we never send it again.
            with patch("azurelinuxagent.ga.telemetry_service.add_event") as mock_add_event:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.report_event") as patch_report_event:
                    test_str = "Test exception, Guid: {0}".format(str(uuid.uuid4()))
                    patch_report_event.side_effect = Exception(test_str)

                    telemetry_handler.enqueue_event(TelemetryEvent())
                    TestTelemetryServiceHandler._stop_handler(telemetry_handler, timeout=0.01)

                    self._assert_error_event_reported(mock_add_event, test_str, operation=WALAEventOperation.UnhandledError)

    def _create_extension_event(self, # pylint: disable=invalid-name,too-many-arguments
                               size=0,
                               name="DummyExtension",
                               op=WALAEventOperation.Unknown,
                               is_success=True,
                               duration=0,
                               version=CURRENT_VERSION,
                               message="DummyMessage"):
        event_data = self._get_event_data(name=size if size != 0 else name,
                op=op,
                is_success=is_success,
                duration=duration,
                version=version,
                message=random_generator(size) if size != 0 else message)
        event_file = os.path.join(self.event_dir, "{0}.tld".format(int(time.time() * 1000000)))
        with open(event_file, 'wb+') as fd: # pylint: disable=invalid-name
            fd.write(event_data.encode('utf-8'))

    @staticmethod
    def _get_event_data(duration, is_success, message, name, op, version, eventId=1): # pylint: disable=invalid-name,too-many-arguments
        event = TelemetryEvent(eventId, TestTelemetryServiceHandler._TEST_EVENT_PROVIDER_ID) # pylint: disable=redefined-outer-name
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Name, name))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Version, str(version)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Operation, op))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.OperationSuccess, is_success))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Message, message))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Duration, duration))

        data = get_properties(event)
        return json.dumps(data)

    @patch("azurelinuxagent.common.event.TELEMETRY_EVENT_PROVIDER_ID", _TEST_EVENT_PROVIDER_ID)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_it_should_enqueue_and_send_events_properly(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_telemetry_service_handler() as telemetry_handler:
            monitor_handler = CollectAndEnqueueEventsPeriodicOperation(telemetry_handler.enqueue_event)
            self._create_extension_event(message="Message-Test")

            test_mtime = 1000  # epoch time, in ms
            test_opcodename = datetime.fromtimestamp(test_mtime).strftime(logger.Logger.LogTimeFormatInUTC)
            test_eventtid = 42
            test_eventpid = 24
            test_taskname = "TEST_TaskName"

            with patch("os.path.getmtime", return_value=test_mtime):
                with patch('os.getpid', return_value=test_eventpid):
                    with patch("threading.Thread.ident", new_callable=PropertyMock(return_value=test_eventtid)):
                        with patch("threading.Thread.getName", return_value=test_taskname):
                            monitor_handler.run()

            TestTelemetryServiceHandler._stop_handler(telemetry_handler)
            # Validating the crafted message by the collect_and_send_events call.
            self.assertEqual(1, len(telemetry_handler.event_calls), "Only 1 event should be sent")

            _, collected_event = telemetry_handler.event_calls[0]

            # Some of those expected values come from the mock protocol and imds client set up during test initialization
            osutil = get_osutil()
            osversion = u"{0}:{1}-{2}-{3}:{4}".format(platform.system(), DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME,
                                                      platform.release())

            sample_message = '<Event id="1"><![CDATA[' \
                             '<Param Name="Name" Value="DummyExtension" T="mt:wstr" />' \
                             '<Param Name="Version" Value="{0}" T="mt:wstr" />' \
                             '<Param Name="Operation" Value="Unknown" T="mt:wstr" />' \
                             '<Param Name="OperationSuccess" Value="True" T="mt:bool" />' \
                             '<Param Name="Message" Value="Message-Test" T="mt:wstr" />' \
                             '<Param Name="Duration" Value="0" T="mt:uint64" />' \
                             '<Param Name="GAVersion" Value="{1}" T="mt:wstr" />' \
                             '<Param Name="ContainerId" Value="c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2" T="mt:wstr" />' \
                             '<Param Name="OpcodeName" Value="{2}" T="mt:wstr" />' \
                             '<Param Name="EventTid" Value="{3}" T="mt:uint64" />' \
                             '<Param Name="EventPid" Value="{4}" T="mt:uint64" />' \
                             '<Param Name="TaskName" Value="{5}" T="mt:wstr" />' \
                             '<Param Name="KeywordName" Value="" T="mt:wstr" />' \
                             '<Param Name="ExtensionType" Value="json" T="mt:wstr" />' \
                             '<Param Name="IsInternal" Value="False" T="mt:bool" />' \
                             '<Param Name="OSVersion" Value="{6}" T="mt:wstr" />' \
                             '<Param Name="ExecutionMode" Value="IAAS" T="mt:wstr" />' \
                             '<Param Name="RAM" Value="{7}" T="mt:uint64" />' \
                             '<Param Name="Processors" Value="{8}" T="mt:uint64" />' \
                             '<Param Name="TenantName" Value="db00a7755a5e4e8a8fe4b19bc3b330c3" T="mt:wstr" />' \
                             '<Param Name="RoleName" Value="MachineRole" T="mt:wstr" />' \
                             '<Param Name="RoleInstanceName" Value="b61f93d0-e1ed-40b2-b067-22c243233448.MachineRole_IN_0" T="mt:wstr" />' \
                             '<Param Name="Location" Value="uswest" T="mt:wstr" />' \
                             '<Param Name="SubscriptionId" Value="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" T="mt:wstr" />' \
                             '<Param Name="ResourceGroupName" Value="test-rg" T="mt:wstr" />' \
                             '<Param Name="VMId" Value="99999999-8888-7777-6666-555555555555" T="mt:wstr" />' \
                             '<Param Name="ImageOrigin" Value="2468" T="mt:uint64" />' \
                             ']]></Event>'.format(AGENT_VERSION, CURRENT_AGENT, test_opcodename, test_eventtid,
                                                  test_eventpid, test_taskname, osversion, int(osutil.get_total_mem()),
                                                  osutil.get_processor_cores())

            self.assertIn(sample_message.encode('utf-8'), collected_event)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_small_events(self, mock_lib_dir):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_telemetry_service_handler() as telemetry_handler:
            sizes = [15, 15, 15, 15]  # get the powers of 2 - 2**16 is the limit

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            CollectAndEnqueueEventsPeriodicOperation(telemetry_handler.enqueue_event).run()

            # The send_event call would be called each time, as we are filling up the buffer up to the brim for each call.
            TestTelemetryServiceHandler._stop_handler(telemetry_handler)
            self.assertEqual(4, len(telemetry_handler.event_calls))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_large_events(self, mock_lib_dir):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_telemetry_service_handler() as telemetry_handler:
            sizes = [17, 17, 17]  # get the powers of 2

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
                CollectAndEnqueueEventsPeriodicOperation(telemetry_handler.enqueue_event).run()
                TestTelemetryServiceHandler._stop_handler(telemetry_handler)
                self.assertEqual(3, patch_periodic_warn.call_count)

                # The send_event call should never be called as the events are larger than 2**16.
                self.assertEqual(0, len(telemetry_handler.event_calls))