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
import datetime
import os
import random
import re
import string

from azurelinuxagent.common import event, logger
from azurelinuxagent.common.cgroup import CGroup, CpuCgroup, MemoryCgroup, MetricValue
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator, UnexpectedProcessesInCGroupException
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.event import EVENTS_DIRECTORY
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.ga.monitor import get_monitor_handler, MonitorHandler, PeriodicOperation, \
    ResetPeriodicLogMessagesOperation, PollResourceUsageOperation
from tests.common.mock_cgroup_commands import mock_cgroup_commands
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances


def random_generator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))


@contextlib.contextmanager
def _create_monitor_handler(enabled_operations=None, iterations=1):
    """
    Creates an instance of MonitorHandler that
        * Uses a mock_wire_protocol for network requests,
        * Executes only the operations given in the 'enabled_operations' parameter,
        * Runs its main loop only the number of times given in the 'iterations' parameter, and
        * Does not sleep at the end of each iteration

    The returned MonitorHandler is augmented with 2 methods:
        * get_mock_wire_protocol() - returns the mock protocol
        * run_and_wait() - invokes run() and wait() on the MonitorHandler

    """
    if enabled_operations is None:
        enabled_operations = []

    def run(self):
        if len(enabled_operations) == 0 or self._name in enabled_operations:  # pylint: disable=protected-access
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

        ResetPeriodicLogMessagesOperation().run()

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
    def test_send_extension_metrics_telemetry(self, patch_poll_all_tracked, patch_add_event,  # pylint: disable=unused-argument
                                              patch_add_metric, *args):
        patch_poll_all_tracked.return_value = [MetricValue("Process", "% Processor Time", 1, 1),
                                               MetricValue("Memory", "Total Memory Usage", 1, 1),
                                               MetricValue("Memory", "Max Memory Usage", 1, 1)]

        PollResourceUsageOperation().run()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(3, patch_add_metric.call_count)  # Three metrics being sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    def test_send_extension_metrics_telemetry_for_empty_cgroup(self, patch_poll_all_tracked,  # pylint: disable=unused-argument
                                                               patch_add_metric,*args):
        patch_poll_all_tracked.return_value = []

        PollResourceUsageOperation().run()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(0, patch_add_metric.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_memory_cgroup_exceptions_errno2(self, patch_periodic_warn,  # pylint: disable=unused-argument
                                                                                       patch_get_memory_usage,
                                                                                       patch_add_metric, *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_get_memory_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(MemoryCgroup("cgroup_name", "/test/path"))  # pylint: disable=protected-access

        PollResourceUsageOperation().run()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_cpu_cgroup_exceptions_errno2(self, patch_periodic_warn,  # pylint: disable=unused-argument
                                                                                    patch_cpu_usage, patch_add_metric,
                                                                                    *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_cpu_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(CpuCgroup("cgroup_name", "/test/path"))  # pylint: disable=protected-access

        PollResourceUsageOperation().run()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_for_unsupported_cgroup(self, patch_periodic_warn, patch_add_metric, *args):  # pylint: disable=unused-argument
        CGroupsTelemetry._tracked.append(CGroup("cgroup_name", "/test/path", "io"))  # pylint: disable=protected-access

        PollResourceUsageOperation().run()
        self.assertEqual(1, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

    def test_generate_extension_metrics_telemetry_dictionary(self, *args):  # pylint: disable=unused-argument
        num_polls = 10
        num_extensions = 1

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

        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))  # pylint: disable=protected-access

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


class PollResourceUsageOperationTestCase(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        # ensure cgroups are enabled by forcing a new instance
        CGroupConfigurator._instance = None  # pylint: disable=protected-access
        with mock_cgroup_commands():
            CGroupConfigurator.get_instance().initialize()

    @classmethod
    def tearDownClass(cls):
        CGroupConfigurator._instance = None  # pylint: disable=protected-access
        AgentTestCase.tearDownClass()

    def test_it_should_issue_a_telemetry_event_when_there_are_processes_that_do_not_belong_to_the_agent_cgroup(self):
        with patch.object(CGroupConfigurator.get_instance(), "check_processes_in_agent_cgroup", side_effect=UnexpectedProcessesInCGroupException(["A-TEST-PROCESS"])):
            with patch("azurelinuxagent.ga.monitor.add_event") as add_event_patcher:
                PollResourceUsageOperation().run()

                messages = [kwargs["message"] for (_, kwargs) in add_event_patcher.call_args_list if "The agent's cgroup includes unexpected processes" in kwargs["message"]]

                self.assertEqual(1, len(messages), "Exactly 1 telemetry event should have been reported. Events: {0}".format(messages))

                # The list of processes in the message is an array of strings: "['foo', ..., 'bar']"
                search = re.search(r'\[(?P<processes>.+)\]', messages[0])
                self.assertIsNotNone(search, "The event message is not in the expected format: {0}".format(messages[0]))
                processes = search.group('processes')
                self.assertIn("A-TEST-PROCESS", processes, 'Extra processes were reported as unexpected: {0}'.format(processes))


@patch("azurelinuxagent.common.utils.restutil.http_post")
@patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state')
@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestMonitorFailure(AgentTestCase):

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_error_heartbeat_creates_no_signal(self, patch_report_heartbeat, patch_http_get, patch_add_event, *args):  # pylint: disable=unused-argument

        monitor_handler = get_monitor_handler()
        protocol = WireProtocol('endpoint')
        protocol.update_goal_state = MagicMock()
        with patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol):
            monitor_handler.init_protocols()
            monitor_handler.last_host_plugin_heartbeat = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

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
