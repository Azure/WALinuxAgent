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
# Requires Python 2.4+ and Openssl 1.0+
#
import errno
import os
import random
import time

from azurelinuxagent.ga.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.utils import fileutil
from tests.lib.tools import AgentTestCase, data_dir, patch


def raise_ioerror(*_):
    e = IOError()
    from errno import EIO
    e.errno = EIO
    raise e


def median(lst):
    data = sorted(lst)
    l_len = len(data)
    if l_len < 1:
        return None
    if l_len % 2 == 0:
        return (data[int((l_len - 1) / 2)] + data[int((l_len + 1) / 2)]) / 2.0
    else:
        return data[int((l_len - 1) / 2)]


def generate_metric_list(lst):
    return [float(sum(lst)) / float(len(lst)),
            min(lst),
            max(lst),
            median(lst),
            len(lst)]


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):  # pylint: disable=unused-variable
        waste += random.random()
    return waste


def consume_memory():
    waste = []
    for x in range(1, 3):  # pylint: disable=unused-variable
        waste.append([random.random()] * 10000)
        time.sleep(0.1)
        waste *= 0
    return waste


class TestCGroupsTelemetry(AgentTestCase):
    NumSummarizationValues = 7

    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        # CPU Cgroups compute usage based on /proc/stat and /sys/fs/cgroup/.../cpuacct.stat; use mock data for those
        # files
        original_read_file = fileutil.read_file

        def mock_read_file(filepath, **args):
            if filepath == "/proc/stat":
                filepath = os.path.join(data_dir, "cgroups", "proc_stat_t0")
            elif filepath.endswith("/cpuacct.stat"):
                filepath = os.path.join(data_dir, "cgroups", "cpuacct.stat_t0")
            return original_read_file(filepath, **args)

        cls._mock_read_cpu_cgroup_file = patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=mock_read_file)
        cls._mock_read_cpu_cgroup_file.start()

    @classmethod
    def tearDownClass(cls):
        cls._mock_read_cpu_cgroup_file.stop()

        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)
        CGroupsTelemetry.reset()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        CGroupsTelemetry.reset()

    @staticmethod
    def _track_new_extension_cgroups(num_extensions):
        for i in range(num_extensions):
            dummy_cpu_cgroup = CpuCgroup("dummy_extension_{0}".format(i), "dummy_cpu_path_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = MemoryCgroup("dummy_extension_{0}".format(i), "dummy_memory_path_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

    def _assert_cgroups_are_tracked(self, num_extensions):
        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

    def _assert_polled_metrics_equal(self, metrics, cpu_metric_value, memory_metric_value, max_memory_metric_value, swap_memory_value):
        for metric in metrics:
            self.assertIn(metric.category, ["CPU", "Memory"])
            if metric.category == "CPU":
                self.assertEqual(metric.counter, "% Processor Time")
                self.assertEqual(metric.value, cpu_metric_value)
            if metric.category == "Memory":
                self.assertIn(metric.counter, ["Total Memory Usage", "Max Memory Usage", "Swap Memory Usage"])
                if metric.counter == "Total Memory Usage":
                    self.assertEqual(metric.value, memory_metric_value)
                elif metric.counter == "Max Memory Usage":
                    self.assertEqual(metric.value, max_memory_metric_value)
                elif metric.counter == "Swap Memory Usage":
                    self.assertEqual(metric.value, swap_memory_value)

    def test_telemetry_polling_with_active_cgroups(self, *args):  # pylint: disable=unused-argument
        num_extensions = 3

        self._track_new_extension_cgroups(num_extensions)

        with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                    with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.try_swap_memory_usage") as patch_try_swap_memory_usage:
                        with patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                            with patch("azurelinuxagent.ga.cgroup.CGroup.is_active") as patch_is_active:
                                patch_is_active.return_value = True

                                current_cpu = 30
                                current_memory = 209715200
                                current_max_memory = 471859200
                                current_swap_memory = 20971520

                                # 1 CPU metric + 1 Current Memory + 1 Max memory + 1 swap memory
                                num_of_metrics_per_extn_expected = 4
                                patch_get_cpu_usage.return_value = current_cpu
                                patch_get_memory_usage.return_value = current_memory  # example 200 MB
                                patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB
                                patch_try_swap_memory_usage.return_value = current_swap_memory  # example 20MB
                                num_polls = 12

                                for data_count in range(1, num_polls + 1):  # pylint: disable=unused-variable
                                    metrics = CGroupsTelemetry.poll_all_tracked()

                                    self.assertEqual(len(metrics), num_extensions * num_of_metrics_per_extn_expected)
                                    self._assert_polled_metrics_equal(metrics, current_cpu, current_memory, current_max_memory, current_swap_memory)

    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.ga.cgroup.CGroup.is_active", return_value=False)
    def test_telemetry_polling_with_inactive_cgroups(self, *_):
        num_extensions = 5
        no_extensions_expected = 0  # pylint: disable=unused-variable

        self._track_new_extension_cgroups(num_extensions)
        self._assert_cgroups_are_tracked(num_extensions)

        metrics = CGroupsTelemetry.poll_all_tracked()

        for i in range(num_extensions):
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertEqual(len(metrics), 0)

    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage")
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage")
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage")
    @patch("azurelinuxagent.ga.cgroup.CGroup.is_active")
    def test_telemetry_polling_with_changing_cgroups_state(self, patch_is_active, patch_get_cpu_usage,  # pylint: disable=unused-argument
                                                           patch_get_mem, patch_get_max_mem, *args):
        num_extensions = 5
        self._track_new_extension_cgroups(num_extensions)

        patch_is_active.return_value = True

        no_extensions_expected = 0  # pylint: disable=unused-variable
        expected_data_count = 1  # pylint: disable=unused-variable

        current_cpu = 30
        current_memory = 209715200
        current_max_memory = 471859200

        patch_get_cpu_usage.return_value = current_cpu
        patch_get_mem.return_value = current_memory  # example 200 MB
        patch_get_max_mem.return_value = current_max_memory  # example 450 MB

        self._assert_cgroups_are_tracked(num_extensions)
        CGroupsTelemetry.poll_all_tracked()

        self._assert_cgroups_are_tracked(num_extensions)

        patch_is_active.return_value = False
        patch_get_cpu_usage.side_effect = raise_ioerror
        patch_get_mem.side_effect = raise_ioerror
        patch_get_max_mem.side_effect = raise_ioerror

        CGroupsTelemetry.poll_all_tracked()

        for i in range(num_extensions):
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

    # mocking get_proc_stat to make it run on Mac and other systems. This test does not need to read the values of the
    # /proc/stat file on the filesystem.
    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_telemetry_polling_to_not_generate_transient_logs_ioerror_file_not_found(self, patch_periodic_warn):
        num_extensions = 1
        self._track_new_extension_cgroups(num_extensions)
        self.assertEqual(0, patch_periodic_warn.call_count)

        # Not expecting logs present for io_error with errno=errno.ENOENT
        io_error_2 = IOError()
        io_error_2.errno = errno.ENOENT

        with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=io_error_2):
            poll_count = 1
            for data_count in range(poll_count, 10):  # pylint: disable=unused-variable
                CGroupsTelemetry.poll_all_tracked()
                self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_telemetry_polling_to_generate_transient_logs_ioerror_permission_denied(self, patch_periodic_warn):
        num_extensions = 1
        num_controllers = 1
        is_active_check_per_controller = 2
        self._track_new_extension_cgroups(num_extensions)

        self.assertEqual(0, patch_periodic_warn.call_count)

        # Expecting logs to be present for different kind of errors
        io_error_3 = IOError()
        io_error_3.errno = errno.EPERM

        with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=io_error_3):
            poll_count = 1
            expected_count_per_call = num_controllers + is_active_check_per_controller
            # get_max_memory_usage memory controller would generate a log statement, and each cgroup would invoke a
            # is active check raising an exception

            for data_count in range(poll_count, 10):  # pylint: disable=unused-variable
                CGroupsTelemetry.poll_all_tracked()
                self.assertEqual(poll_count * expected_count_per_call, patch_periodic_warn.call_count)

    def test_telemetry_polling_to_generate_transient_logs_index_error(self):
        num_extensions = 1
        self._track_new_extension_cgroups(num_extensions)

        # Generating a different kind of error (non-IOError) to check the logging.
        # Trying to invoke IndexError during the getParameter call
        with patch("azurelinuxagent.common.utils.fileutil.read_file", return_value=''):
            with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
                expected_call_count = 1  # 1 periodic warning for memory
                for data_count in range(1, 10):  # pylint: disable=unused-variable
                    CGroupsTelemetry.poll_all_tracked()
                    self.assertEqual(expected_call_count, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.try_swap_memory_usage")
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage")
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage")
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage")
    @patch("azurelinuxagent.ga.cgroup.CGroup.is_active")
    def test_telemetry_calculations(self,  patch_is_active, patch_get_cpu_usage, patch_get_memory_usage, patch_get_memory_max_usage, patch_try_memory_swap_usage,
                                    *args):  # pylint: disable=unused-argument
        num_polls = 10
        num_extensions = 1

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        swap_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

        self._track_new_extension_cgroups(num_extensions)
        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))

        for i in range(num_polls):
            patch_is_active.return_value = True
            patch_get_cpu_usage.return_value = cpu_percent_values[i]
            patch_get_memory_usage.return_value = memory_usage_values[i]
            patch_get_memory_max_usage.return_value = max_memory_usage_values[i]
            patch_try_memory_swap_usage.return_value = swap_usage_values[i]

            metrics = CGroupsTelemetry.poll_all_tracked()

            # 1 CPU metric + 1 Current Memory + 1 Max memory + 1 swap memory
            self.assertEqual(len(metrics), 4 * num_extensions)
            self._assert_polled_metrics_equal(metrics, cpu_percent_values[i], memory_usage_values[i], max_memory_usage_values[i], swap_usage_values[i])

    def test_cgroup_tracking(self, *args):  # pylint: disable=unused-argument
        num_extensions = 5
        num_controllers = 2
        self._track_new_extension_cgroups(num_extensions)
        self._assert_cgroups_are_tracked(num_extensions)
        self.assertEqual(num_extensions * num_controllers, len(CGroupsTelemetry._tracked))

    def test_cgroup_is_tracked(self, *args):  # pylint: disable=unused-argument
        num_extensions = 5
        self._track_new_extension_cgroups(num_extensions)
        self._assert_cgroups_are_tracked(num_extensions)
        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_cpu_dummy_path"))
        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_memory_dummy_path"))

    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage", side_effect=raise_ioerror)
    def test_process_cgroup_metric_with_no_memory_cgroup_mounted(self, *args):  # pylint: disable=unused-argument
        num_extensions = 5
        self._track_new_extension_cgroups(num_extensions)

        with patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
            with patch("azurelinuxagent.ga.cgroup.CGroup.is_active") as patch_is_active:
                patch_is_active.return_value = True

                current_cpu = 30
                patch_get_cpu_usage.return_value = current_cpu

                poll_count = 1

                for data_count in range(poll_count, 10):  # pylint: disable=unused-variable
                    metrics = CGroupsTelemetry.poll_all_tracked()

                    self.assertEqual(len(metrics), num_extensions * 1)  # Only CPU populated
                    self._assert_polled_metrics_equal(metrics, current_cpu, 0, 0, 0)

    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage", side_effect=raise_ioerror)
    def test_process_cgroup_metric_with_no_cpu_cgroup_mounted(self, *args):  # pylint: disable=unused-argument
        num_extensions = 5

        self._track_new_extension_cgroups(num_extensions)

        with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.try_swap_memory_usage") as patch_try_swap_memory_usage:
                    with patch("azurelinuxagent.ga.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        current_memory = 209715200
                        current_max_memory = 471859200
                        current_swap_memory = 20971520

                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB
                        patch_try_swap_memory_usage.return_value = current_swap_memory  # example 20MB
                        num_polls = 10
                        for data_count in range(1, num_polls + 1):  # pylint: disable=unused-variable
                            metrics = CGroupsTelemetry.poll_all_tracked()
                            # Memory is only populated, CPU is not. Thus 3 metrics for memory.
                            self.assertEqual(len(metrics), num_extensions * 3)
                            self._assert_polled_metrics_equal(metrics, 0, current_memory, current_max_memory, current_swap_memory)

    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_max_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage", side_effect=raise_ioerror)
    def test_extension_telemetry_not_sent_for_empty_perf_metrics(self, *args):  # pylint: disable=unused-argument
        num_extensions = 5
        self._track_new_extension_cgroups(num_extensions)

        with patch("azurelinuxagent.ga.cgroup.CGroup.is_active") as patch_is_active:

            patch_is_active.return_value = False
            poll_count = 1

            for data_count in range(poll_count, 10):  # pylint: disable=unused-variable
                metrics = CGroupsTelemetry.poll_all_tracked()
                self.assertEqual(0, len(metrics))

    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_usage")
    @patch("azurelinuxagent.ga.cgroup.CpuCgroup.get_cpu_throttled_time")
    @patch("azurelinuxagent.ga.cgroup.CGroup.is_active")
    def test_cgroup_telemetry_should_not_report_cpu_negative_value(self, patch_is_active, path_get_throttled_time, patch_get_cpu_usage):

        num_polls = 5
        num_extensions = 1

        # only verifying calculations and not validity of the values.
        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls-1)]
        cpu_percent_values.append(-1)
        cpu_throttled_values = [random.randint(0, 60 * 60) for _ in range(num_polls)]

        dummy_cpu_cgroup = CpuCgroup("dummy_extension_name", "dummy_cpu_path")
        CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)
        self.assertEqual(1, len(CGroupsTelemetry._tracked))

        for i in range(num_polls):
            patch_is_active.return_value = True
            patch_get_cpu_usage.return_value = cpu_percent_values[i]
            path_get_throttled_time.return_value = cpu_throttled_values[i]

            CGroupsTelemetry._track_throttled_time = True
            metrics = CGroupsTelemetry.poll_all_tracked()

            # 1 CPU metric + 1 CPU throttled
            # ignore CPU metrics from telemetry if cpu cgroup reports negative value
            if i < num_polls-1:
                self.assertEqual(len(metrics), 2 * num_extensions)
            else:
                self.assertEqual(len(metrics), 0)

            for metric in metrics:
                self.assertGreaterEqual(metric.value, 0, "telemetry should not report negative value")
