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
from azurelinuxagent.ga.cgroupcontroller import MetricValue, MetricsCounter
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, is_log_collection_allowed, \
    get_log_collector_monitor_handler
from azurelinuxagent.ga.cpucontroller import CpuControllerV1, CpuControllerV2
from azurelinuxagent.ga.memorycontroller import MemoryControllerV1, MemoryControllerV2
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.wire_protocol_data import DATA_FILE
from tests.lib.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances, skip_if_predicate_true, \
    is_python_version_26, data_dir


class CgroupVersions:
    V1 = "v1"
    V2 = "v2"


@contextlib.contextmanager
def _create_collect_logs_handler(iterations=1, cgroup_version=CgroupVersions.V1, cgroups_enabled=True, collect_logs_conf=True, cgroupv2_resource_limiting_conf=False):
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
                    with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs", return_value=collect_logs_conf):

                        # Grab the singleton to patch it
                        cgroups_configurator_singleton = CGroupConfigurator.get_instance()

                        if cgroup_version == CgroupVersions.V1:
                            with patch.object(cgroups_configurator_singleton, "enabled", return_value=cgroups_enabled):
                                def run_and_wait():
                                    collect_logs_handler.run()
                                    collect_logs_handler.join()

                                collect_logs_handler = get_collect_logs_handler()
                                collect_logs_handler.get_mock_wire_protocol = lambda: protocol
                                collect_logs_handler.run_and_wait = run_and_wait
                                yield collect_logs_handler
                        else:
                            with patch("azurelinuxagent.ga.collect_logs.conf.get_enable_cgroup_v2_resource_limiting", return_value=cgroupv2_resource_limiting_conf):
                                with patch.object(cgroups_configurator_singleton, "enabled", return_value=False):
                                    with patch("azurelinuxagent.ga.cgroupconfigurator.CGroupConfigurator._Impl.using_cgroup_v2", return_value=True):
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
        # 1) It should be enabled in the configuration.
        # 2) The system must be using cgroups to manage services - needed for resource limiting of the log collection. The
        # agent currently fully supports resource limiting for v1, but only supports log collector resource limiting for v2
        # if enabled via configuration.
        #    This condition is True if either:
        #       a. cgroup usage in the agent is enabled; OR
        #       b. the machine is using cgroup v2 and v2 resource limiting is enabled in the configuration.
        # 3) The python version must be greater than 2.6 in order to support the ZipFile library used when collecting.

        # Note, cgroups should not be in an 'enabled' state in the configurator if v2 is in use. Resource governance is
        # not fully supported on v2 yet.

        # If collect logs is not enabled in the configuration, then log collection should always be disabled

        # Case 1:
        #   - Cgroups are enabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=True, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=True, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 2:
        #   - Cgroups are enabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=True, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=False, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 3:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V2, cgroupv2_resource_limiting_conf=True, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 4:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V2, cgroupv2_resource_limiting_conf=False, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 5:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=True, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 6:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag false
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=False, collect_logs_conf=False):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # If collect logs is enabled in the configuration and cgroups are enbaled in the configurator, then log collection should always be enabled

        # Case 7:
        #   - Cgroups are enabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=True, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=True, collect_logs_conf=True):
            self.assertEqual(True, is_log_collection_allowed(), "Log collection should have been enabled")

        # Case 8:
        #   - Cgroups are enabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=True, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=False, collect_logs_conf=True):
            self.assertEqual(True, is_log_collection_allowed(), "Log collection should have been enabled")

        # If collect logs is enabled in the configuration and v2 is in use with the v2 resource limiting conf enabled, then log collection should always be enabled

        # Case 9:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V2, cgroupv2_resource_limiting_conf=True, collect_logs_conf=True):
            self.assertEqual(True, is_log_collection_allowed(), "Log collection should have been enabled")

        # If collect logs is enabled in the configuration and v2 is in use but the v2 resource limiting conf disabled, then log collection should always be disabled

        # Case 10:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V2, cgroupv2_resource_limiting_conf=False, collect_logs_conf=True):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # If collect logs is enabled in the configuration but cgroups are disabled in the configurator and v2 is not in use, then log collections should always be disabled

        # Case 11:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is True
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=True, collect_logs_conf=True):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

        # Case 12:
        #   - Cgroups are disabled in the configurator
        #   - Cgroup v2 is not in use
        #   - Cgroup v2 resource limiting conf is False
        #   - collect logs config flag true
        with _create_collect_logs_handler(cgroups_enabled=False, cgroup_version=CgroupVersions.V1, cgroupv2_resource_limiting_conf=False, collect_logs_conf=True):
            self.assertEqual(False, is_log_collection_allowed(), "Log collection should not have been enabled")

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
def _create_log_collector_monitor_handler(iterations=1, cgroup_version=CgroupVersions.V1):
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

            def mock_read_file_v1(filepath, **args):
                if filepath == "/proc/stat":
                    filepath = os.path.join(data_dir, "cgroups", "v1", "proc_stat_t0")
                elif filepath.endswith("/cpuacct.stat"):
                    filepath = os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t0")
                return original_read_file(filepath, **args)

            def mock_read_file_v2(filepath, **args):
                if filepath == "/proc/uptime":
                    filepath = os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t0")
                elif filepath.endswith("/cpu.stat"):
                    filepath = os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t0")
                return original_read_file(filepath, **args)

            mock_read_file = None
            cgroups = []
            if cgroup_version == "v1":
                mock_read_file = mock_read_file_v1
                cgroups = [
                    CpuControllerV1("test", "dummy_cpu_path"),
                    MemoryControllerV1("test", "dummy_memory_path")
                ]
            else:
                mock_read_file = mock_read_file_v2
                cgroups = [
                    CpuControllerV2("test", "dummy_cpu_path"),
                    MemoryControllerV2("test", "dummy_memory_path")
                ]

            with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=mock_read_file):
                def run_and_wait():
                    monitor_log_collector.run()
                    monitor_log_collector.join()

                monitor_log_collector = get_log_collector_monitor_handler(cgroups)
                monitor_log_collector.run_and_wait = run_and_wait
                yield monitor_log_collector


class TestLogCollectorMonitorHandler(AgentTestCase):

    def test_get_max_recorded_metrics(self):
        with _create_log_collector_monitor_handler(iterations=2) as log_collector_monitor_handler:
            nonlocal_vars = {
                'cpu_iteration': 0,
                'mem_iteration': 0,
                'multiplier': 5
            }

            def get_different_cpu_metrics(**kwargs):    # pylint: disable=W0613
                metrics = [MetricValue("Process", MetricsCounter.PROCESSOR_PERCENT_TIME, "service", 4.5), MetricValue("Process", MetricsCounter.THROTTLED_TIME, "service", nonlocal_vars['cpu_iteration']*nonlocal_vars['multiplier'] + 10.000)]
                nonlocal_vars['cpu_iteration'] += 1
                return metrics

            def get_different_memory_metrics(**kwargs):     # pylint: disable=W0613
                metrics = [MetricValue("Memory", MetricsCounter.TOTAL_MEM_USAGE, "service", 20),
                          MetricValue("Memory", MetricsCounter.ANON_MEM_USAGE, "service", 15),
                          MetricValue("Memory", MetricsCounter.CACHE_MEM_USAGE, "service", nonlocal_vars['mem_iteration']*nonlocal_vars['multiplier'] + 5),
                          MetricValue("Memory", MetricsCounter.MAX_MEM_USAGE, "service", 30),
                          MetricValue("Memory", MetricsCounter.SWAP_MEM_USAGE, "service", 0)]
                nonlocal_vars['mem_iteration'] += 1
                return metrics

            with patch("azurelinuxagent.ga.cpucontroller._CpuController.get_tracked_metrics", side_effect=get_different_cpu_metrics):
                with patch("azurelinuxagent.ga.memorycontroller._MemoryController.get_tracked_metrics", side_effect=get_different_memory_metrics):
                    log_collector_monitor_handler.run_and_wait()
                    max_recorded_metrics = log_collector_monitor_handler.get_max_recorded_metrics()
                    self.assertEqual(len(max_recorded_metrics), 7)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.PROCESSOR_PERCENT_TIME], 4.5)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.THROTTLED_TIME], 15.0)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.TOTAL_MEM_USAGE], 20)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.ANON_MEM_USAGE], 15)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.CACHE_MEM_USAGE], 10)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.MAX_MEM_USAGE], 30)
                    self.assertEqual(max_recorded_metrics[MetricsCounter.SWAP_MEM_USAGE], 0)

    def test_verify_log_collector_memory_limit_exceeded(self):
        with _create_log_collector_monitor_handler() as log_collector_monitor_handler:
            cache_exceeded = [MetricValue("Process", MetricsCounter.PROCESSOR_PERCENT_TIME, "service", 4.5),
                              MetricValue("Process", MetricsCounter.THROTTLED_TIME, "service", 10.281),
                              MetricValue("Memory", MetricsCounter.TOTAL_MEM_USAGE, "service", 170 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.ANON_MEM_USAGE, "service", 15 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.CACHE_MEM_USAGE, "service", 160 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.MAX_MEM_USAGE, "service", 171 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.SWAP_MEM_USAGE, "service", 0)]
            with patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler._poll_resource_usage", return_value=cache_exceeded):
                with patch("os._exit") as mock_exit:
                    log_collector_monitor_handler.run_and_wait()
                    self.assertEqual(mock_exit.call_count, 1)

        with _create_log_collector_monitor_handler() as log_collector_monitor_handler:
            anon_exceeded = [MetricValue("Process", MetricsCounter.PROCESSOR_PERCENT_TIME, "service", 4.5),
                              MetricValue("Process", MetricsCounter.THROTTLED_TIME, "service", 10.281),
                              MetricValue("Memory", MetricsCounter.TOTAL_MEM_USAGE, "service", 170 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.ANON_MEM_USAGE, "service", 30 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.CACHE_MEM_USAGE, "service", 140 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.MAX_MEM_USAGE, "service", 171 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.SWAP_MEM_USAGE, "service", 0)]
            with patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler._poll_resource_usage", return_value=anon_exceeded):
                with patch("os._exit") as mock_exit:
                    log_collector_monitor_handler.run_and_wait()
                    self.assertEqual(mock_exit.call_count, 1)

        with _create_log_collector_monitor_handler(cgroup_version=CgroupVersions.V2) as log_collector_monitor_handler:
            mem_throttled_exceeded = [MetricValue("Process", MetricsCounter.PROCESSOR_PERCENT_TIME, "service", 4.5),
                              MetricValue("Process", MetricsCounter.THROTTLED_TIME, "service", 10.281),
                              MetricValue("Memory", MetricsCounter.TOTAL_MEM_USAGE, "service", 170 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.ANON_MEM_USAGE, "service", 15 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.CACHE_MEM_USAGE, "service", 140 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.MAX_MEM_USAGE, "service", 171 * 1024 ** 2),
                              MetricValue("Memory", MetricsCounter.SWAP_MEM_USAGE, "service", 0),
                              MetricValue("Memory", MetricsCounter.MEM_THROTTLED, "service", 11)]
            with patch("azurelinuxagent.ga.collect_logs.LogCollectorMonitorHandler._poll_resource_usage", return_value=mem_throttled_exceeded):
                with patch("os._exit") as mock_exit:
                    log_collector_monitor_handler.run_and_wait()
                    self.assertEqual(mock_exit.call_count, 1)
