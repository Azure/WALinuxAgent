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
import os

from azurelinuxagent.common import logger, conf
from azurelinuxagent.ga.cgroup import CpuCgroup, MemoryCgroup, MetricValue
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, is_log_collection_allowed, \
    get_log_collector_monitor_handler
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.wire_protocol_data import DATA_FILE
from tests.lib.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances, skip_if_predicate_true, \
    is_python_version_26, data_dir


@contextlib.contextmanager
def _create_collect_logs_handler(iterations=1, cgroups_enabled=True, collect_logs_conf=True):
    """
    Creates an instance of CollectLogsHandler that
        * Uses a mock_wire_protocol for network requests,
        * Runs its main loop only the number of times given in the 'iterations' parameter, and
        * Does not sleep at the end of each iteration

    The returned CollectLogsHandler is augmented with 2 methods:
        * get_mock_wire_protocol() - returns the mock protocol
        * run_and_wait() - invokes run() and wait() on the CollectLogsHandler

    """
    with mock_wire_protocol(DATA_FILE) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.collect_logs.get_protocol_util", return_value=protocol_util):
            with patch("azurelinuxagent.ga.collect_logs.CollectLogsHandler.stopped",
                       side_effect=[False] * iterations + [True]):
                with patch("time.sleep"):
                    # Grab the singleton to patch it
                    cgroups_configurator_singleton = CGroupConfigurator.get_instance()
                    with patch.object(cgroups_configurator_singleton, "enabled", return_value=cgroups_enabled):
                        with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs",
                                   return_value=collect_logs_conf):
                            def run_and_wait():
                                collect_logs_handler.run()
                                collect_logs_handler.join()

                            collect_logs_handler = get_collect_logs_handler()
                            collect_logs_handler.get_mock_wire_protocol = lambda: protocol
                            collect_logs_handler.run_and_wait = run_and_wait
                            yield collect_logs_handler


@skip_if_predicate_true(is_python_version_26, "Disabled on Python 2.6")
class TestCollectLogs(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        prefix = "UnitTest"
        logger.DEFAULT_LOGGER = Logger(prefix=prefix)

        self.archive_path = os.path.join(self.tmp_dir, "logs.zip")
        self.mock_archive_path = patch("azurelinuxagent.ga.collect_logs.COMPRESSED_ARCHIVE_PATH", self.archive_path)
        self.mock_archive_path.start()

        self.logger_path = os.path.join(self.tmp_dir, "waagent.log")
        self.mock_logger_path = patch.object(conf, "get_agent_log_file", return_value=self.logger_path)
        self.mock_logger_path.start()

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def tearDown(self):
        if os.path.exists(self.archive_path):
            os.remove(self.archive_path)
        self.mock_archive_path.stop()
        if os.path.exists(self.logger_path):
            os.remove(self.logger_path)
        self.mock_logger_path.stop()
        AgentTestCase.tearDown(self)

    def _create_dummy_archive(self, size=1024):
        with open(self.archive_path, "wb") as f:
            f.truncate(size)

    def test_it_should_only_collect_logs_if_conditions_are_met(self):
        # In order to collect logs, three conditions have to be met:
        # 1) the flag must be set to true in the conf file
        # 2) cgroups must be managing services
        # 3) python version 2.7+ which is automatically true for these tests since they are disabled on py2.6

        # cgroups not enabled, config flag false
        with _create_collect_logs_handler(cgroups_enabled=False, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # cgroups enabled, config flag false
        with _create_collect_logs_handler(cgroups_enabled=True, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # cgroups not enabled, config flag true
        with _create_collect_logs_handler(cgroups_enabled=False, collect_logs_conf=True):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # cgroups enabled, config flag true
        with _create_collect_logs_handler(cgroups_enabled=True, collect_logs_conf=True):
            self.assertEqual(True, is_log_collection_allowed(), "Log collection should have been enabled")

    def test_it_uploads_logs_when_collection_is_successful(self):
        archive_size = 42

        def mock_run_command(*_, **__):
            return self._create_dummy_archive(size=archive_size)

        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.shellutil.run_command", side_effect=mock_run_command):
                def http_put_handler(url, content, **__):
                    if self.is_host_plugin_put_logs_request(url):
                        http_put_handler.counter += 1
                        http_put_handler.archive = content
                        return MockHttpResponse(status=200)
                    return None

                http_put_handler.counter = 0
                http_put_handler.archive = b""
                protocol = collect_logs_handler.get_mock_wire_protocol()
                protocol.set_http_handlers(http_put_handler=http_put_handler)

                collect_logs_handler.run_and_wait()
                self.assertEqual(http_put_handler.counter, 1, "The PUT API to upload logs should have been called once")
                self.assertTrue(os.path.exists(self.archive_path), "The archive file should exist on disk")
                self.assertEqual(archive_size, len(http_put_handler.archive),
                                 "The archive file should have {0} bytes, not {1}".format(archive_size,
                                                                                          len(http_put_handler.archive)))

    def test_it_does_not_upload_logs_when_collection_is_unsuccessful(self):
        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.shellutil.run_command",
                       side_effect=Exception("test exception")):
                def http_put_handler(url, _, **__):
                    if self.is_host_plugin_put_logs_request(url):
                        http_put_handler.counter += 1
                        return MockHttpResponse(status=200)
                    return None

                http_put_handler.counter = 0
                protocol = collect_logs_handler.get_mock_wire_protocol()
                protocol.set_http_handlers(http_put_handler=http_put_handler)

                collect_logs_handler.run_and_wait()
                self.assertFalse(os.path.exists(self.archive_path), "The archive file should not exist on disk")
                self.assertEqual(http_put_handler.counter, 0, "The PUT API to upload logs shouldn't have been called")


@contextlib.contextmanager
def _create_log_collector_monitor_handler(iterations=1):
    """
    Creates an instance of LogCollectorMonitorHandler that
        * Runs its main loop only the number of times given in the 'iterations' parameter, and
        * Does not sleep at the end of each iteration

    The returned CollectLogsHandler is augmented with 2 methods:
        * run_and_wait() - invokes run() and wait() on the CollectLogsHandler

    """
    with patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler.stopped",
               side_effect=[False] * iterations + [True]):
        with patch("time.sleep"):

            original_read_file = fileutil.read_file

            def mock_read_file(filepath, **args):
                if filepath == "/proc/stat":
                    filepath = os.path.join(data_dir, "cgroups", "proc_stat_t0")
                elif filepath.endswith("/cpuacct.stat"):
                    filepath = os.path.join(data_dir, "cgroups", "cpuacct.stat_t0")
                return original_read_file(filepath, **args)

            with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=mock_read_file):
                def run_and_wait():
                    monitor_log_collector.run()
                    monitor_log_collector.join()

                cgroups = [
                    CpuCgroup("test", "dummy_cpu_path"),
                    MemoryCgroup("test", "dummy_memory_path")
                ]
                monitor_log_collector = get_log_collector_monitor_handler(cgroups)
                monitor_log_collector.run_and_wait = run_and_wait
                yield monitor_log_collector


class TestLogCollectorMonitorHandler(AgentTestCase):

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler._poll_resource_usage")
    def test_send_extension_metrics_telemetry(self, patch_poll_resource_usage, patch_add_metric):
        with _create_log_collector_monitor_handler() as log_collector_monitor_handler:
            patch_poll_resource_usage.return_value = [MetricValue("Process", "% Processor Time", "service", 1),
                                                      MetricValue("Process", "Throttled Time", "service", 1),
                                                      MetricValue("Memory", "Total Memory Usage", "service", 1),
                                                      MetricValue("Memory", "Max Memory Usage", "service", 1),
                                                      MetricValue("Memory", "Swap Memory Usage", "service", 1)
                                                      ]
            log_collector_monitor_handler.run_and_wait()
            self.assertEqual(1, patch_poll_resource_usage.call_count)
            self.assertEqual(5, patch_add_metric.call_count)  # Five metrics being sent.

    @patch("os._exit", side_effect=Exception)
    @patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler._poll_resource_usage")
    def test_verify_log_collector_memory_limit_exceeded(self, patch_poll_resource_usage, mock_exit):
        with _create_log_collector_monitor_handler() as log_collector_monitor_handler:
            with patch("azurelinuxagent.ga.cgroupconfigurator.LOGCOLLECTOR_MEMORY_LIMIT", 8):
                patch_poll_resource_usage.return_value = [MetricValue("Process", "% Processor Time", "service", 1),
                                                          MetricValue("Process", "Throttled Time", "service", 1),
                                                          MetricValue("Memory", "Total Memory Usage", "service", 9),
                                                          MetricValue("Memory", "Max Memory Usage", "service", 7),
                                                          MetricValue("Memory", "Swap Memory Usage", "service", 0)

                                                          ]
                try:
                    log_collector_monitor_handler.run_and_wait()
                except Exception:
                    self.assertEqual(mock_exit.call_count, 1)
