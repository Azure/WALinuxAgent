# -*- coding: utf-8 -*-
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
import contextlib
import os
import random
import string

from azurelinuxagent.common import event, logger
from azurelinuxagent.ga.cgroup import CpuCgroup, MemoryCgroup, MetricValue, _REPORT_EVERY_HOUR
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.event import EVENTS_DIRECTORY
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.ga.monitor import get_monitor_handler, PeriodicOperation, SendImdsHeartbeat, \
    ResetPeriodicLogMessages, SendHostPluginHeartbeat, PollResourceUsage, \
    ReportNetworkErrors, ReportNetworkConfigurationChanges, PollSystemWideResourceUsage
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.wire_protocol_data import DATA_FILE
from tests.lib.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances


def random_generator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))


@contextlib.contextmanager
def _mock_wire_protocol():
    # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
    # reuse a previous state
    clear_singleton_instances(ProtocolUtil)

    with mock_wire_protocol(DATA_FILE) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.monitor.get_protocol_util", return_value=protocol_util):
            yield protocol


class MonitorHandlerTestCase(AgentTestCase):
    def test_it_should_invoke_all_periodic_operations(self):
        def periodic_operation_run(self):
            invoked_operations.append(self.__class__.__name__)

        with _mock_wire_protocol():
            with patch("azurelinuxagent.ga.monitor.MonitorHandler.stopped", side_effect=[False, True, False, True]):
                with patch("time.sleep"):
                    with patch.object(PeriodicOperation, "run", side_effect=periodic_operation_run, autospec=True):
                        with patch("azurelinuxagent.common.conf.get_monitor_network_configuration_changes") as monitor_network_changes:
                            for network_changes in [True, False]:
                                monitor_network_changes.return_value = network_changes

                                invoked_operations = []

                                monitor_handler = get_monitor_handler()
                                monitor_handler.run()
                                monitor_handler.join()

                                expected_operations = [
                                    PollResourceUsage.__name__,
                                    PollSystemWideResourceUsage.__name__,
                                    ReportNetworkErrors.__name__,
                                    ResetPeriodicLogMessages.__name__,
                                    SendHostPluginHeartbeat.__name__,
                                    SendImdsHeartbeat.__name__,
                                ]

                                if network_changes:
                                    expected_operations.append(ReportNetworkConfigurationChanges.__name__)

                                invoked_operations.sort()
                                expected_operations.sort()

                                self.assertEqual(invoked_operations, expected_operations, "The monitor thread did not invoke the expected operations")


class SendHostPluginHeartbeatOperationTestCase(AgentTestCase, HttpRequestPredicates):
    def test_it_should_report_host_ga_health(self):
        with _mock_wire_protocol() as protocol:
            def http_post_handler(url, _, **__):
                if self.is_health_service_request(url):
                    http_post_handler.health_service_posted = True
                    return MockHttpResponse(status=200)
                return None
            http_post_handler.health_service_posted = False
            protocol.set_http_handlers(http_post_handler=http_post_handler)

            health_service = HealthService(protocol.get_endpoint())

            SendHostPluginHeartbeat(protocol, health_service).run()

            self.assertTrue(http_post_handler.health_service_posted, "The monitor thread did not report host ga plugin health")

    def test_it_should_report_a_telemetry_event_when_host_plugin_is_not_healthy(self):
        with _mock_wire_protocol() as protocol:
            # the error triggers only after ERROR_STATE_DELTA_DEFAULT
            with patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered', return_value=True):
                with patch('azurelinuxagent.common.event.EventLogger.add_event') as add_event_patcher:
                    def http_get_handler(url, *_, **__):
                        if self.is_host_plugin_health_request(url):
                            return MockHttpResponse(status=503)
                        return None
                    protocol.set_http_handlers(http_get_handler=http_get_handler)

                    health_service = HealthService(protocol.get_endpoint())

                    SendHostPluginHeartbeat(protocol, health_service).run()

                    heartbeat_events = [kwargs for _, kwargs in add_event_patcher.call_args_list if kwargs['op'] == 'HostPluginHeartbeatExtended']
                    self.assertTrue(len(heartbeat_events) == 1, "The monitor thread should have reported exactly 1 telemetry event for an unhealthy host ga plugin")
                    self.assertFalse(heartbeat_events[0]['is_success'], 'The reported event should indicate failure')

    def test_it_should_not_send_a_health_signal_when_the_hearbeat_fails(self):
        with _mock_wire_protocol() as protocol:
            with patch('azurelinuxagent.common.event.EventLogger.add_event') as add_event_patcher:
                health_service_post_requests = []

                def http_get_handler(url, *_, **__):
                    if self.is_host_plugin_health_request(url):
                        del health_service_post_requests[:]  # clear the requests; after this error there should be no more POSTs
                        raise IOError('A CLIENT ERROR')
                    return None

                def http_post_handler(url, _, **__):
                    if self.is_health_service_request(url):
                        health_service_post_requests.append(url)
                        return MockHttpResponse(status=200)
                    return None

                protocol.set_http_handlers(http_get_handler=http_get_handler, http_post_handler=http_post_handler)

                health_service = HealthService(protocol.get_endpoint())

                SendHostPluginHeartbeat(protocol, health_service).run()

                self.assertEqual(0, len(health_service_post_requests), "No health signals should have been posted: {0}".format(health_service_post_requests))

                heartbeat_events = [kwargs for _, kwargs in add_event_patcher.call_args_list if kwargs['op'] == 'HostPluginHeartbeat']
                self.assertTrue(len(heartbeat_events) == 1, "The monitor thread should have reported exactly 1 telemetry event for an unhealthy host ga plugin")
                self.assertFalse(heartbeat_events[0]['is_success'], 'The reported event should indicate failure')
                self.assertIn('A CLIENT ERROR', heartbeat_events[0]['message'], 'The failure does not include the expected message')


class ResetPeriodicLogMessagesOperationTestCase(AgentTestCase, HttpRequestPredicates):
    def test_it_should_clear_periodic_log_messages(self):
        logger.reset_periodic()

        # Adding 100 different messages
        expected = 100
        for i in range(expected):
            logger.periodic_info(logger.EVERY_DAY, "Test {0}".format(i))

        actual = len(logger.DEFAULT_LOGGER.periodic_messages)

        if actual != expected:
            raise Exception('Test setup error: the periodic messages were not added. Got: {0} Expected: {1}'.format(actual, expected))

        ResetPeriodicLogMessages().run()

        self.assertEqual(0, len(logger.DEFAULT_LOGGER.periodic_messages), "The monitor thread did not reset the periodic log messages")


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
        protocol.client.update_goal_state = MagicMock()
        self.get_protocol = patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol)
        self.get_protocol.start()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        CGroupsTelemetry.reset()
        self.get_protocol.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    def test_send_extension_metrics_telemetry(self, patch_poll_all_tracked,  # pylint: disable=unused-argument
                                              patch_add_metric, *args):
        patch_poll_all_tracked.return_value = [MetricValue("Process", "% Processor Time", "service", 1),
                                               MetricValue("Memory", "Total Memory Usage", "service", 1),
                                               MetricValue("Memory", "Max Memory Usage", "service", 1, _REPORT_EVERY_HOUR),
                                               MetricValue("Memory", "Swap Memory Usage", "service", 1, _REPORT_EVERY_HOUR)
                                               ]

        PollResourceUsage().run()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(4, patch_add_metric.call_count)  # Four metrics being sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    def test_send_extension_metrics_telemetry_for_empty_cgroup(self, patch_poll_all_tracked,  # pylint: disable=unused-argument
                                                               patch_add_metric, *args):
        patch_poll_all_tracked.return_value = []

        PollResourceUsage().run()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(0, patch_add_metric.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_memory_cgroup_exceptions_errno2(self, patch_periodic_warn,  # pylint: disable=unused-argument
                                                                                       patch_get_memory_usage,
                                                                                       patch_add_metric, *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_get_memory_usage.side_effect = ioerror

        CGroupsTelemetry._tracked["/test/path"] = MemoryCgroup("cgroup_name", "/test/path")

        PollResourceUsage().run()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_cpu_cgroup_exceptions_errno2(self, patch_periodic_warn,  # pylint: disable=unused-argument
                                                                                    patch_cpu_usage, patch_add_metric,
                                                                                    *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_cpu_usage.side_effect = ioerror

        CGroupsTelemetry._tracked["/test/path"] = CpuCgroup("cgroup_name", "/test/path")

        PollResourceUsage().run()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.


class TestPollSystemWideResourceUsage(AgentTestCase):

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_used_and_available_system_memory")
    def test_send_system_memory_metrics(self, path_get_system_memory, patch_add_metric, *args): # pylint: disable=unused-argument
        path_get_system_memory.return_value = (234.45, 123.45)
        PollSystemWideResourceUsage().run()

        self.assertEqual(1, path_get_system_memory.call_count)
        self.assertEqual(2, patch_add_metric.call_count)  # 2 metrics being sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.monitor.PollSystemWideResourceUsage.poll_system_memory_metrics")
    def test_send_system_memory_metrics_empty(self, path_poll_system_memory_metrics, patch_add_metric, # pylint: disable=unused-argument
                                        *args):
        path_poll_system_memory_metrics.return_value = []
        PollSystemWideResourceUsage().run()

        self.assertEqual(1, path_poll_system_memory_metrics.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # Zero metrics being sent.