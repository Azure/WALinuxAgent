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
import json
import os
import platform
import re
import tempfile
import time
import uuid
from datetime import datetime, timedelta

from mock import MagicMock, Mock, patch, PropertyMock

from azurelinuxagent.common import logger
from azurelinuxagent.common.datacontract import get_properties
from azurelinuxagent.common.event import WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import HttpError, ServiceStoppedError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.factory import get_osutil
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import event_to_v1
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, \
    GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import restutil, fileutil
from azurelinuxagent.common.version import CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, AGENT_VERSION, CURRENT_AGENT, \
    DISTRO_CODE_NAME
from azurelinuxagent.ga.collect_telemetry_events import _CollectAndEnqueueEventsPeriodicOperation
from azurelinuxagent.ga.send_telemetry_events import get_send_telemetry_events_handler
from tests.ga.test_monitor import random_generator
from tests.protocol.mocks import MockHttpResponse, mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import AgentTestCase, clear_singleton_instances, mock_sleep
from tests.utils.event_logger_tools import EventLoggerTools


class TestSendTelemetryEventsHandler(AgentTestCase, HttpRequestPredicates):
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
    def _create_send_telemetry_events_handler(self, timeout=0.5, start_thread=True, batching_queue_limit=1):
        def http_post_handler(url, body, **__):
            if self.is_telemetry_request(url):
                send_telemetry_events_handler.event_calls.append((datetime.now(), body))
                return MockHttpResponse(status=200)
            return None

        with mock_wire_protocol(DATA_FILE, http_post_handler=http_post_handler) as protocol:
            protocol_util = MagicMock()
            protocol_util.get_protocol = Mock(return_value=protocol)
            send_telemetry_events_handler = get_send_telemetry_events_handler(protocol_util)
            send_telemetry_events_handler.event_calls = []
            with patch("azurelinuxagent.ga.send_telemetry_events.SendTelemetryEventsHandler._MIN_EVENTS_TO_BATCH",
                       batching_queue_limit):
                with patch("azurelinuxagent.ga.send_telemetry_events.SendTelemetryEventsHandler._MAX_TIMEOUT", timeout):

                    send_telemetry_events_handler.get_mock_wire_protocol = lambda: protocol
                    if start_thread:
                        send_telemetry_events_handler.start()
                        self.assertTrue(send_telemetry_events_handler.is_alive(), "Thread didn't start properly!")
                    yield send_telemetry_events_handler

    @staticmethod
    def _stop_handler(telemetry_handler, timeout=0.001):
        # Giving it some grace time to finish execution and then stopping thread
        time.sleep(timeout)
        telemetry_handler.stop()

    def _assert_test_data_in_event_body(self, telemetry_handler, test_events):
        # Stop the thread and Wait for the queue and thread to join
        TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)

        for telemetry_event in test_events:
            event_str = event_to_v1(telemetry_event)
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
        with self._create_send_telemetry_events_handler() as telemetry_handler:

            telemetry_handler.get_mock_wire_protocol().set_http_handlers(http_post_handler=http_post_handler)

            with patch("azurelinuxagent.common.event.add_event") as mock_add_event:
                telemetry_handler.enqueue_event(TelemetryEvent())
                TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)
                for msg in expected_msgs:
                    self._assert_error_event_reported(mock_add_event, msg)

    def test_it_should_send_events_properly(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]

        with self._create_send_telemetry_events_handler() as telemetry_handler:
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_send_as_soon_as_events_available_in_queue_with_minimal_batching_limits(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]

        with self._create_send_telemetry_events_handler() as telemetry_handler:
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

        with self._create_send_telemetry_events_handler(timeout=0.1) as telemetry_handler:

            # Do nothing for some time
            time.sleep(0.3)

            # Ensure that no events were transmitted by the telemetry handler during this time, i.e. telemetry thread was idle
            self.assertEqual(0, len(telemetry_handler.event_calls), "Unwanted calls to telemetry")

            # Now enqueue data and verify send_telemetry_events sends them asap
            for test_event in events:
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_honor_batch_time_limits_before_sending_telemetry(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]
        wait_time = timedelta(seconds=10)
        orig_sleep = time.sleep

        with patch("time.sleep", lambda *_: orig_sleep(0.01)):
            with patch("azurelinuxagent.ga.send_telemetry_events.SendTelemetryEventsHandler._MIN_BATCH_WAIT_TIME", wait_time):
                with self._create_send_telemetry_events_handler(batching_queue_limit=5) as telemetry_handler:
                    for test_event in events:
                        telemetry_handler.enqueue_event(test_event)

                    self.assertEqual(0, len(telemetry_handler.event_calls), "No events should have been logged")
                    TestSendTelemetryEventsHandler._stop_handler(telemetry_handler, timeout=0.01)

        wait_time = timedelta(seconds=0.2)
        with patch("time.sleep", lambda *_: orig_sleep(0.05)):
            with patch("azurelinuxagent.ga.send_telemetry_events.SendTelemetryEventsHandler._MIN_BATCH_WAIT_TIME", wait_time):
                with self._create_send_telemetry_events_handler(batching_queue_limit=5) as telemetry_handler:
                    test_start_time = datetime.now()
                    for test_event in events:
                        telemetry_handler.enqueue_event(test_event)

                    while not telemetry_handler.event_calls and (test_start_time + timedelta(seconds=1)) > datetime.now():
                        # Wait for event calls to be made, wait a max of 1 secs
                        orig_sleep(0.1)

                    self.assertGreater(len(telemetry_handler.event_calls), 0, "No event calls made at all!")
                    self._assert_test_data_in_event_body(telemetry_handler, events)
                    for event_time, _ in telemetry_handler.event_calls:
                        elapsed = event_time - test_start_time
                        # Technically we should send out data after 0.2 secs, but keeping a buffer of 1sec while testing
                        self.assertLessEqual(elapsed, timedelta(seconds=1), "Request was not sent properly")

    def test_it_should_clear_queue_before_stopping(self):
        events = [TelemetryEvent(eventId=ustr(uuid.uuid4())), TelemetryEvent(eventId=ustr(uuid.uuid4()))]
        wait_time = timedelta(seconds=10)

        with patch("time.sleep", lambda *_: mock_sleep(0.01)):
            with patch("azurelinuxagent.ga.send_telemetry_events.SendTelemetryEventsHandler._MIN_BATCH_WAIT_TIME", wait_time):
                with self._create_send_telemetry_events_handler(batching_queue_limit=5) as telemetry_handler:
                    for test_event in events:
                        telemetry_handler.enqueue_event(test_event)

                    self.assertEqual(0, len(telemetry_handler.event_calls), "No events should have been logged")
                    TestSendTelemetryEventsHandler._stop_handler(telemetry_handler, timeout=0.01)
                    # After the service is asked to stop, we should send all data in the queue
                    self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_honor_batch_queue_limits_before_sending_telemetry(self):

        batch_limit = 5

        with self._create_send_telemetry_events_handler(batching_queue_limit=batch_limit) as telemetry_handler:
            events = []

            for _ in range(batch_limit-1):
                test_event = TelemetryEvent(eventId=ustr(uuid.uuid4()))
                events.append(test_event)
                telemetry_handler.enqueue_event(test_event)

            self.assertEqual(0, len(telemetry_handler.event_calls), "No events should have been logged")

            for _ in range(batch_limit):
                test_event = TelemetryEvent(eventId=ustr(uuid.uuid4()))
                events.append(test_event)
                telemetry_handler.enqueue_event(test_event)

            self._assert_test_data_in_event_body(telemetry_handler, events)

    def test_it_should_raise_on_enqueue_if_service_stopped(self):
        with self._create_send_telemetry_events_handler(start_thread=False) as telemetry_handler:
            # Ensure the thread is stopped
            telemetry_handler.stop()
            with self.assertRaises(ServiceStoppedError) as context_manager:
                telemetry_handler.enqueue_event(TelemetryEvent(eventId=ustr(uuid.uuid4())))

            exception = context_manager.exception
            self.assertIn("{0} is stopped, not accepting anymore events".format(telemetry_handler.get_thread_name()),
                          str(exception))

    def test_it_should_honour_the_incoming_order_of_events(self):

        with self._create_send_telemetry_events_handler(timeout=0.3, start_thread=False) as telemetry_handler:
            for index in range(5):
                telemetry_handler.enqueue_event(TelemetryEvent(eventId=index))

            telemetry_handler.start()
            self.assertTrue(telemetry_handler.is_alive(), "Thread not alive")
            TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)
            _, event_body = telemetry_handler.event_calls[0]
            event_orders = re.findall(r'<Event id=\"(\d+)\"><!\[CDATA\[]]></Event>', event_body)
            self.assertEqual(sorted(event_orders), event_orders, "Events not ordered correctly")

    def test_send_telemetry_events_should_report_event_if_wireserver_returns_http_error(self):

        test_str = "A test exception, Guid: {0}".format(str(uuid.uuid4()))

        def http_post_handler(url, _, **__):
            if self.is_telemetry_request(url):
                return HttpError(test_str)
            return None

        self._setup_and_assert_bad_request_scenarios(http_post_handler, [test_str])

    def test_send_telemetry_events_should_report_event_when_http_post_returning_503(self):

        def http_post_handler(url, _, **__):
            if self.is_telemetry_request(url):
                return MockHttpResponse(restutil.httpclient.SERVICE_UNAVAILABLE)
            return None

        expected_msgs = ["[ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed]",
                        "[HTTP Failed] Status Code 503"]

        self._setup_and_assert_bad_request_scenarios(http_post_handler, expected_msgs)

    def test_send_telemetry_events_should_add_event_on_unexpected_errors(self):

        with self._create_send_telemetry_events_handler(timeout=0.1) as telemetry_handler:

            with patch("azurelinuxagent.ga.send_telemetry_events.add_event") as mock_add_event:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.report_event") as patch_report_event:
                    test_str = "Test exception, Guid: {0}".format(str(uuid.uuid4()))
                    patch_report_event.side_effect = Exception(test_str)

                    telemetry_handler.enqueue_event(TelemetryEvent())
                    TestSendTelemetryEventsHandler._stop_handler(telemetry_handler, timeout=0.01)

                    self._assert_error_event_reported(mock_add_event, test_str, operation=WALAEventOperation.UnhandledError)

    def _create_extension_event(self,
                               size=0,
                               name="DummyExtension",
                               message="DummyMessage"):
        event_data = self._get_event_data(name=size if size != 0 else name,
                message=random_generator(size) if size != 0 else message)
        event_file = os.path.join(self.event_dir, "{0}.tld".format(int(time.time() * 1000000)))
        with open(event_file, 'wb+') as file_descriptor:
            file_descriptor.write(event_data.encode('utf-8'))

    @staticmethod
    def _get_event_data(message, name):
        event = TelemetryEvent(1, TestSendTelemetryEventsHandler._TEST_EVENT_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Name, name))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Version, str(CURRENT_VERSION)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Operation, WALAEventOperation.Unknown))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.OperationSuccess, True))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Message, message))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Duration, 0))

        data = get_properties(event)
        return json.dumps(data)

    @patch("azurelinuxagent.common.event.TELEMETRY_EVENT_PROVIDER_ID", _TEST_EVENT_PROVIDER_ID)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_it_should_enqueue_and_send_events_properly(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_send_telemetry_events_handler() as telemetry_handler:
            monitor_handler = _CollectAndEnqueueEventsPeriodicOperation(telemetry_handler)
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

            TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)
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

            self.assertIn(sample_message, collected_event)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_small_events(self, mock_lib_dir):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_send_telemetry_events_handler() as telemetry_handler:
            sizes = [15, 15, 15, 15]  # get the powers of 2 - 2**16 is the limit

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            _CollectAndEnqueueEventsPeriodicOperation(telemetry_handler).run()

            # The send_event call would be called each time, as we are filling up the buffer up to the brim for each call.
            TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)
            self.assertEqual(4, len(telemetry_handler.event_calls))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_large_events(self, mock_lib_dir):
        mock_lib_dir.return_value = self.lib_dir

        with self._create_send_telemetry_events_handler() as telemetry_handler:
            sizes = [17, 17, 17]  # get the powers of 2

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
                _CollectAndEnqueueEventsPeriodicOperation(telemetry_handler).run()
                TestSendTelemetryEventsHandler._stop_handler(telemetry_handler)
                self.assertEqual(3, patch_periodic_warn.call_count)

                # The send_event call should never be called as the events are larger than 2**16.
                self.assertEqual(0, len(telemetry_handler.event_calls))