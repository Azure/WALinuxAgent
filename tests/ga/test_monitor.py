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
import datetime
import contextlib
import json
import os
import platform
import random
import string
import tempfile
import time
from datetime import timedelta

from azurelinuxagent.common.protocol.util import ProtocolUtil

from azurelinuxagent.common import event, logger
from azurelinuxagent.common.cgroup import CGroup, CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry, MetricValue
from azurelinuxagent.common.datacontract import get_properties
from azurelinuxagent.common.event import add_event, WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.version import AGENT_VERSION, CURRENT_VERSION, CURRENT_AGENT, DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME
from azurelinuxagent.ga.monitor import generate_extension_metrics_telemetry_dictionary, get_monitor_handler, MonitorHandler, PeriodicOperation
from tests.protocol.mockwiredata import DATA_FILE
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances, PropertyMock
from tests.utils.event_logger_tools import EventLoggerTools


def random_generator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))

@contextlib.contextmanager
def _create_monitor_handler(enabled_operations=[], iterations=1):
    def run(self):
        if len(enabled_operations) == 0 or self._name in enabled_operations:
            run.original_definition(self)
    run.original_definition = PeriodicOperation.run

    with mock_wire_protocol(DATA_FILE) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.monitor.get_protocol_util", return_value=protocol_util):
            with patch.object(PeriodicOperation, "run", side_effect=run, autospec=True):
                with patch("azurelinuxagent.ga.monitor.MonitorHandler.stopped", side_effect=[False] * iterations + [True]):
                    with patch("time.sleep"):
                        def run_and_wait():
                            monitor_handler.run()
                            monitor_handler.join()

                        monitor_handler = get_monitor_handler()
                        monitor_handler.get_mock_wire_protocol = lambda: protocol
                        monitor_handler.run_and_wait = run_and_wait
                        yield monitor_handler


class TestMonitor(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        prefix = "UnitTest"
        logger.DEFAULT_LOGGER = Logger(prefix=prefix)

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_it_should_invoke_all_periodic_operations(self):
        invoked_operations = []

        with _create_monitor_handler() as monitor_handler:
            def mock_run(self):
                invoked_operations.append(self._name)

            with patch.object(PeriodicOperation, "run", side_effect=mock_run, spec=MonitorHandler.run):
                monitor_handler.run_and_wait()

                expected_operations = [
                    "reset_loggers", "collect_and_send_events", "send_telemetry_heartbeat",
                    "poll_telemetry_metrics usage", "send_telemetry_metrics usage", "send_host_plugin_heartbeat",
                    "send_imds_heartbeat", "log_altered_network_configuration"
                ]

                self.assertEqual(invoked_operations.sort(), expected_operations.sort(), "The monitor thread did not invoke the expected operations")

    def test_it_should_report_host_ga_health(self):
        with _create_monitor_handler(enabled_operations=["send_host_plugin_heartbeat"]) as monitor_handler:
            def http_post_handler(url, _, **__):
                if self.is_health_service_request(url):
                    http_post_handler.health_service_posted = True
                    return MockHttpResponse(status=200)
                return None
            http_post_handler.health_service_posted = False

            monitor_handler.get_mock_wire_protocol().set_http_handlers(http_post_handler=http_post_handler)

            monitor_handler.run_and_wait()

            self.assertTrue(http_post_handler.health_service_posted, "The monitor thread did not report host ga plugin health")

    def test_it_should_report_a_telemetry_event_when_host_plugin_is_not_healthy(self):
        with _create_monitor_handler(enabled_operations=["send_host_plugin_heartbeat"]) as monitor_handler:
            def http_get_handler(url, *_, **__):
                if self.is_host_plugin_health_request(url):
                    return MockHttpResponse(status=503)
                return None

            monitor_handler.get_mock_wire_protocol().set_http_handlers(http_get_handler=http_get_handler)

            # the error triggers only after ERROR_STATE_DELTA_DEFAULT
            with patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered', return_value=True):
                with patch('azurelinuxagent.common.event.EventLogger.add_event') as add_event_patcher:
                    monitor_handler.run_and_wait()

                    heartbeat_events = [kwargs for _, kwargs in add_event_patcher.call_args_list if kwargs['op'] == 'HostPluginHeartbeatExtended']
                    self.assertTrue(len(heartbeat_events) == 1, "The monitor thread should have reported exactly 1 telemetry event for an unhealthy host ga plugin")
                    self.assertFalse(heartbeat_events[0]['is_success'], 'The reported event should indicate failure')

    def test_it_should_clear_periodic_log_messages(self):
        # Adding 100 different messages
        for i in range(100):
            logger.periodic_info(logger.EVERY_DAY, "Test {0}".format(i))

        if len(logger.DEFAULT_LOGGER.periodic_messages) != 100:
            raise Exception('Test setup error: the periodic messages were not added')

        with _create_monitor_handler(enabled_operations=["reset_loggers"]) as monitor_handler:
            monitor_handler.run_and_wait()

            self.assertEqual(len(logger.DEFAULT_LOGGER.periodic_messages), 0, "The monitor thread did not reset the periodic log messages")


class TestEventMonitoring(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.lib_dir = tempfile.mkdtemp()
        self.event_dir = os.path.join(self.lib_dir, event.EVENTS_DIRECTORY)

        EventLoggerTools.initialize_event_logger(self.event_dir)

    def tearDown(self):
        fileutil.rm_dirs(self.lib_dir)

    def _create_extension_event(self,
                               size=0,
                               name="DummyExtension",
                               op=WALAEventOperation.Unknown,
                               is_success=True,
                               duration=0,
                               version=CURRENT_VERSION,
                               message="DummyMessage"):
        event_data = TestEventMonitoring._get_event_data(name=size if size != 0 else name,
                op=op,
                is_success=is_success,
                duration=duration,
                version=version,
                message=random_generator(size) if size != 0 else message)
        event_file = os.path.join(self.event_dir, "{0}.tld".format(int(time.time() * 1000000)))
        with open(event_file, 'wb+') as fd:
            fd.write(event_data.encode('utf-8'))

    @staticmethod
    def _get_event_data(duration, is_success, message, name, op, version, eventId=1):
        event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
        event.parameters.append(TelemetryEventParam('Name', name))
        event.parameters.append(TelemetryEventParam('Version', str(version)))
        event.parameters.append(TelemetryEventParam('Operation', op))
        event.parameters.append(TelemetryEventParam('OperationSuccess', is_success))
        event.parameters.append(TelemetryEventParam('Message', message))
        event.parameters.append(TelemetryEventParam('Duration', duration))

        data = get_properties(event)
        return json.dumps(data)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events(self, mock_lib_dir, patch_send_event, *_):
        mock_lib_dir.return_value = self.lib_dir

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:
            self._create_extension_event(message="Message-Test")

            test_mtime = 1000  # epoch time, in ms
            test_opcodename = datetime.datetime.fromtimestamp(test_mtime).strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
            test_eventtid = 42
            test_eventpid = 24
            test_taskname = "TEST_TaskName"

            with patch("os.path.getmtime", return_value=test_mtime):
                with patch('os.getpid', return_value=test_eventpid):
                    with patch("threading.Thread.ident", new_callable=PropertyMock(return_value=test_eventtid)):
                        with patch("threading.Thread.getName", return_value=test_taskname):
                            monitor_handler.run_and_wait()

            # Validating the crafted message by the collect_and_send_events call.
            self.assertEqual(1, patch_send_event.call_count)
            send_event_call_args = monitor_handler.get_mock_wire_protocol().client.send_event.call_args[0]

            # Some of those expected values come from the mock protocol and imds client set up during test initialization
            osutil = get_osutil()
            osversion = u"{0}:{1}-{2}-{3}:{4}".format(platform.system(), DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME,platform.release())

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
                             '<Param Name="VMName" Value="MachineRole_IN_0" T="mt:wstr" />' \
                             '<Param Name="TenantName" Value="db00a7755a5e4e8a8fe4b19bc3b330c3" T="mt:wstr" />' \
                             '<Param Name="RoleName" Value="MachineRole" T="mt:wstr" />' \
                             '<Param Name="RoleInstanceName" Value="MachineRole_IN_0" T="mt:wstr" />' \
                             '<Param Name="Location" Value="uswest" T="mt:wstr" />' \
                             '<Param Name="SubscriptionId" Value="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" T="mt:wstr" />' \
                             '<Param Name="ResourceGroupName" Value="test-rg" T="mt:wstr" />' \
                             '<Param Name="VMId" Value="99999999-8888-7777-6666-555555555555" T="mt:wstr" />' \
                             '<Param Name="ImageOrigin" Value="2468" T="mt:uint64" />' \
                             ']]></Event>'.format(AGENT_VERSION, CURRENT_AGENT, test_opcodename, test_eventtid,
                                                  test_eventpid, test_taskname, osversion, int(osutil.get_total_mem()),
                                                  osutil.get_processor_cores())

            self.maxDiff = None
            self.assertEqual(sample_message, send_event_call_args[1])

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_small_events(self, mock_lib_dir, patch_send_event, *_):
        mock_lib_dir.return_value = self.lib_dir

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:

            sizes = [15, 15, 15, 15]  # get the powers of 2 - 2**16 is the limit

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            monitor_handler.run_and_wait()

            # The send_event call would be called each time, as we are filling up the buffer up to the brim for each call.

            self.assertEqual(4, patch_send_event.call_count)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_large_events(self, mock_lib_dir, patch_send_event, *_):
        mock_lib_dir.return_value = self.lib_dir

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:

            sizes = [17, 17, 17]  # get the powers of 2

            for power in sizes:
                size = 2 ** power
                self._create_extension_event(size)

            with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
                monitor_handler.run_and_wait()

                self.assertEqual(3, patch_periodic_warn.call_count)

                # The send_event call should never be called as the events are larger than 2**16.
                self.assertEqual(0, patch_send_event.call_count)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_http_post_returning_503(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_dir)

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:
            def http_post_handler(url, _, **__):
                if self.is_telemetry_request(url):
                    return MockHttpResponse(restutil.httpclient.SERVICE_UNAVAILABLE)
                return None

            protocol = monitor_handler.get_mock_wire_protocol()
            protocol.set_http_handlers(http_post_handler=http_post_handler)

            sizes = [1, 2, 3]  # get the powers of 2, and multiple by 1024.

            for power in sizes:
                size = 2 ** power * 1024
                self._create_extension_event(size)

            with patch("azurelinuxagent.common.logger.warn") as mock_warn:
                monitor_handler.run_and_wait()
                self.assertEqual(1, mock_warn.call_count)
                self.assertEqual("[ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed] "
                                 "URI http://{0}/machine?comp=telemetrydata  [HTTP Failed] Status Code 503".format(protocol.get_endpoint()),
                                 mock_warn.call_args[0][2])
                self.assertEqual(0, len(os.listdir(self.event_dir)))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_send_event_generating_exception(self, mock_lib_dir, *args):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_dir)

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:
            sizes = [1, 2, 3]  # get the powers of 2, and multiple by 1024.

            for power in sizes:
                size = 2 ** power * 1024
                self._create_extension_event(size)

            # This test validates that if we hit an issue while sending an event, we never send it again.
            with patch("azurelinuxagent.common.logger.warn") as mock_warn:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.send_event") as patch_send_event:
                    patch_send_event.side_effect = Exception()

                    monitor_handler.run_and_wait()

                    self.assertEqual(1, mock_warn.call_count)
                    self.assertEqual(0, len(os.listdir(self.event_dir)))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_call_wireserver_returns_http_error(self, mock_lib_dir, *args):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_dir)
        add_event(name="MonitorTests", op=WALAEventOperation.HeartBeat, is_success=True, message="Test heartbeat")

        with _create_monitor_handler(enabled_operations=["collect_and_send_events"]) as monitor_handler:
            def http_post_handler(url, _, **__):
                if self.is_telemetry_request(url):
                    return HttpError("A test exception")
                return None

            monitor_handler.get_mock_wire_protocol().set_http_handlers(http_post_handler=http_post_handler)

            with patch("azurelinuxagent.common.logger.warn") as mock_warn:
                monitor_handler.run_and_wait()

                self.assertEqual(1, mock_warn.call_count)
                self.assertEqual(0, len(os.listdir(self.event_dir)))


@patch('azurelinuxagent.common.osutil.get_osutil')
@patch('azurelinuxagent.common.protocol.util.get_protocol_util')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionMetricsDataTelemetry(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        event.init_event_logger(os.path.join(self.tmp_dir, EVENTS_DIRECTORY))
        CGroupsTelemetry.reset()
        clear_singleton_instances(ProtocolUtil)
        protocol = WireProtocol('endpoint')
        protocol.update_goal_state = MagicMock()
        self.get_protocol = patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol)
        self.get_protocol.start()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        CGroupsTelemetry.reset()
        self.get_protocol.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked")
    def test_send_extension_metrics_telemetry(self, patch_report_all_tracked, patch_poll_all_tracked, patch_add_event,
                                              patch_add_metric, *args):
        patch_poll_all_tracked.return_value = [MetricValue("Process", "% Processor Time", 1, 1),
                                               MetricValue("Memory", "Total Memory Usage", 1, 1),
                                               MetricValue("Memory", "Max Memory Usage", 1, 1)]

        patch_report_all_tracked.return_value = {
            "memory": {
                "cur_mem": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())],
                "max_mem": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())]
            },
            "cpu": {
                "cur_cpu": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())]
            }
        }

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(1, patch_report_all_tracked.call_count)
        self.assertEqual(1, patch_add_event.call_count)
        self.assertEqual(3, patch_add_metric.call_count)  # Three metrics being sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked", return_value={})
    def test_send_extension_metrics_telemetry_for_empty_cgroup(self, patch_report_all_tracked, patch_poll_all_tracked,
                                                               patch_add_event, patch_add_metric,*args):
        patch_report_all_tracked.return_value = {}
        patch_poll_all_tracked.return_value = []

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(1, patch_report_all_tracked.call_count)
        self.assertEqual(0, patch_add_event.call_count)
        self.assertEqual(0, patch_add_metric.call_count)
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_memory_cgroup_exceptions_errno2(self, patch_periodic_warn,
                                                                                       patch_get_memory_usage,
                                                                                       patch_add_metric, *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_get_memory_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(MemoryCgroup("cgroup_name", "/test/path"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_cpu_cgroup_exceptions_errno2(self, patch_periodic_warn,
                                                                                    patch_cpu_usage, patch_add_metric,
                                                                                    *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_cpu_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(CpuCgroup("cgroup_name", "/test/path"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_for_unsupported_cgroup(self, patch_periodic_warn, patch_add_metric, *args):
        CGroupsTelemetry._tracked.append(CGroup("cgroup_name", "/test/path", "io"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(1, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

        monitor_handler.stop()

    def test_generate_extension_metrics_telemetry_dictionary(self, *args):
        num_polls = 10
        num_extensions = 1
        num_summarization_values = 7

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

        # no need to initialize the CPU usage, since we mock get_cpu_usage() below
        with patch("azurelinuxagent.common.cgroup.CpuCgroup.initialize_cpu_usage"):
            for i in range(num_extensions):
                dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

                dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                    "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        for i in range(num_polls):
                            patch_is_active.return_value = True
                            patch_get_cpu_usage.return_value = cpu_percent_values[i]
                            patch_get_memory_usage.return_value = memory_usage_values[i]  # example 200 MB
                            patch_get_memory_max_usage.return_value = max_memory_usage_values[i]  # example 450 MB
                            CGroupsTelemetry.poll_all_tracked()

        performance_metrics = CGroupsTelemetry.report_all_tracked()

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                                       performance_metrics=performance_metrics)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertIn("SchemaVersion", message_json)
        self.assertIn("PerfMetrics", message_json)

        collected_metrics = message_json["PerfMetrics"]

        for i in range(num_extensions):
            extn_name = "dummy_extension_{0}".format(i)

            self.assertIn("memory", collected_metrics[extn_name])
            self.assertIn("cur_mem", collected_metrics[extn_name]["memory"])
            self.assertIn("max_mem", collected_metrics[extn_name]["memory"])
            self.assertEqual(len(collected_metrics[extn_name]["memory"]["cur_mem"]), num_summarization_values)
            self.assertEqual(len(collected_metrics[extn_name]["memory"]["max_mem"]), num_summarization_values)

            self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][6], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][6], str)

            self.assertIn("cpu", collected_metrics[extn_name])
            self.assertIn("cur_cpu", collected_metrics[extn_name]["cpu"])
            self.assertEqual(len(collected_metrics[extn_name]["cpu"]["cur_cpu"]), num_summarization_values)

            self.assertIsInstance(collected_metrics[extn_name]["cpu"]["cur_cpu"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["cpu"]["cur_cpu"][6], str)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                                       performance_metrics=None)
        self.assertIn("SchemaVersion", message_json)
        self.assertNotIn("PerfMetrics", message_json)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=2.0,
                                                                       performance_metrics=None)
        self.assertEqual(message_json, None)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version="z",
                                                                       performance_metrics=None)
        self.assertEqual(message_json, None)


@patch("azurelinuxagent.common.utils.restutil.http_post")
@patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state')
@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestMonitorFailure(AgentTestCase):

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_error_heartbeat_creates_no_signal(self, patch_report_heartbeat, patch_http_get, patch_add_event, *args):

        monitor_handler = get_monitor_handler()
        protocol = WireProtocol('endpoint')
        protocol.update_goal_state = MagicMock()
        with patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol):
            monitor_handler.init_protocols()
            monitor_handler.last_host_plugin_heartbeat = datetime.datetime.utcnow() - timedelta(hours=1)

            patch_http_get.side_effect = IOError('client error')
            monitor_handler.send_host_plugin_heartbeat()

            # health report should not be made
            self.assertEqual(0, patch_report_heartbeat.call_count)

            # telemetry with failure details is sent
            self.assertEqual(1, patch_add_event.call_count)
            self.assertEqual('HostPluginHeartbeat', patch_add_event.call_args[1]['op'])
            self.assertTrue('client error' in patch_add_event.call_args[1]['message'])

            self.assertEqual(False, patch_add_event.call_args[1]['is_success'])
            monitor_handler.stop()
