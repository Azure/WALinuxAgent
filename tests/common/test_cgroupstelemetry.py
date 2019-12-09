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

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry, Metric
from azurelinuxagent.common.osutil.default import BASE_CGROUPS, DefaultOSUtil
from azurelinuxagent.common.protocol.restapi import ExtHandlerProperties, ExtHandler
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance
from nose.plugins.attrib import attr
from tests.tools import AgentTestCase, skip_if_predicate_false, skip_if_predicate_true, \
                        are_cgroups_enabled, is_trusty_in_travis, i_am_root, data_dir, patch


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
    for x in range(1, 200000):
        waste += random.random()
    return waste


def consume_memory():
    waste = []
    for x in range(1, 3):
        waste.append([random.random()] * 10000)
        time.sleep(0.1)
        waste *= 0
    return waste


def make_new_cgroup(name="test-cgroup"):
    return CGroupConfigurator.get_instance().create_extension_cgroups(name)


class TestCGroupsTelemetry(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        # CPU Cgroups compute usage based on /proc/stat and /sys/fs/cgroup/.../cpuacct.stat; use mock data for those files
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

    def _assert_cgroup_metrics_equal(self, cpu_usage, memory_usage, max_memory_usage):
        for _, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
            self.assertListEqual(cgroup_metric.get_memory_usage()._data, memory_usage)
            self.assertListEqual(cgroup_metric.get_max_memory_usage()._data, max_memory_usage)
            self.assertListEqual(cgroup_metric.get_cpu_usage()._data, cpu_usage)

    def _assert_cgroup_polling_metrics_equal(self, metrics, cpu_metric_value, memory_metric_value, max_memory_metric_value):
        for metric in metrics:
            self.assertIn(metric.category, ["Process", "Memory"])
            if metric.category == "Process":
                self.assertEqual(metric.counter, "% Processor Time")
                self.assertEqual(metric.value, cpu_metric_value)
            if metric.category == "Memory":
                self.assertIn(metric.counter, ["Total Memory Usage", "Max Memory Usage"])
                if metric.counter == "Total Memory Usage":
                    self.assertEqual(metric.value, memory_metric_value)
                elif metric.counter == "Max Memory Usage":
                    self.assertEqual(metric.value, max_memory_metric_value)

    def test_telemetry_polling_with_active_cgroups(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_usage.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        poll_count = 1

                        for data_count in range(poll_count, 10):
                            metrics = CGroupsTelemetry.poll_all_tracked()
                            self.assertEqual(len(CGroupsTelemetry._cgroup_metrics), num_extensions)
                            self._assert_cgroup_metrics_equal(
                                cpu_usage=[current_cpu] * data_count,
                                memory_usage=[current_memory] * data_count,
                                max_memory_usage=[current_max_memory] * data_count)
                            self.assertEqual(len(metrics), num_extensions * 3)
                            self._assert_cgroup_polling_metrics_equal(metrics, current_cpu, current_memory, current_max_memory)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        self._assert_cgroup_metrics_equal([], [], [])

    def test_telemetry_polling_with_inactive_cgroups(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = False

                        no_extensions_expected = 0
                        data_count = 1
                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_usage.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

                        metrics = CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        self._assert_cgroup_metrics_equal(
                            cpu_usage=[current_cpu] * data_count,
                            memory_usage=[current_memory] * data_count,
                            max_memory_usage=[current_max_memory] * data_count)
                        self.assertEqual(len(metrics), num_extensions * 3)
                        self._assert_cgroup_polling_metrics_equal(metrics, current_cpu, current_memory, current_max_memory)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), no_extensions_expected)
                        self._assert_cgroup_metrics_equal([], [], [])

    def test_telemetry_polling_with_changing_cgroups_state(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        no_extensions_expected = 0
                        expected_data_count = 2

                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_usage.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

                        CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)

                        patch_is_active.return_value = False
                        CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        self._assert_cgroup_metrics_equal(
                            cpu_usage=[current_cpu] * expected_data_count,
                            memory_usage=[current_memory] * expected_data_count,
                            max_memory_usage=[current_max_memory] * expected_data_count)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), no_extensions_expected)
                        self._assert_cgroup_metrics_equal([], [], [])

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_telemetry_polling_to_not_generate_transient_logs_ioerror_file_not_found(self, patch_periodic_warn):
        num_extensions = 1
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(0, patch_periodic_warn.call_count)

        # Not expecting logs present for io_error with errno=errno.ENOENT
        io_error_2 = IOError()
        io_error_2.errno = errno.ENOENT

        with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=io_error_2):
            poll_count = 1
            for data_count in range(poll_count, 10):
                CGroupsTelemetry.poll_all_tracked()
                self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_telemetry_polling_to_generate_transient_logs_ioerror_permission_denied(self, patch_periodic_warn):
        num_extensions = 1
        num_controllers = 2
        is_active_check_per_controller = 2

        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(0, patch_periodic_warn.call_count)

        # Expecting logs to be present for different kind of errors
        io_error_3 = IOError()
        io_error_3.errno = errno.EPERM

        with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=io_error_3):
            poll_count = 1
            expected_count_per_call = num_controllers + is_active_check_per_controller
            # each collect per controller would generate a log statement, and each cgroup would invoke a
            # is active check raising an exception

            for data_count in range(poll_count, 10):
                CGroupsTelemetry.poll_all_tracked()
                self.assertEqual(poll_count * expected_count_per_call, patch_periodic_warn.call_count)

    def test_telemetry_polling_to_generate_transient_logs_index_error(self):
        num_extensions = 1
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        # Generating a different kind of error (non-IOError) to check the logging.
        # Trying to invoke IndexError during the getParameter call
        with patch("azurelinuxagent.common.utils.fileutil.read_file", return_value=''):
            with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
                expected_call_count = 2  # 1 periodic warning for the cpu cgroups, and 1 for memory
                for data_count in range(1, 10):
                    CGroupsTelemetry.poll_all_tracked()
                    self.assertEqual(expected_call_count, patch_periodic_warn.call_count)

    def test_telemetry_calculations(self, *args):
        num_polls = 10
        num_extensions = 1
        num_summarization_values = 7

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

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
                            metrics = CGroupsTelemetry.poll_all_tracked()
                            self.assertEqual(len(metrics), 3 * num_extensions)
                            self._assert_cgroup_polling_metrics_equal(metrics, cpu_percent_values[i], memory_usage_values[i],
                                                                      max_memory_usage_values[i])

        collected_metrics = CGroupsTelemetry.report_all_tracked()
        for i in range(num_extensions):
            name = "dummy_extension_{0}".format(i)

            self.assertIn(name, collected_metrics)
            self.assertIn("memory", collected_metrics[name])
            self.assertIn("cur_mem", collected_metrics[name]["memory"])
            self.assertIn("max_mem", collected_metrics[name]["memory"])
            self.assertEqual(num_summarization_values, len(collected_metrics[name]["memory"]["cur_mem"]))
            self.assertEqual(num_summarization_values, len(collected_metrics[name]["memory"]["max_mem"]))

            self.assertListEqual(generate_metric_list(memory_usage_values),
                                 collected_metrics[name]["memory"]["cur_mem"][0:5])
            self.assertListEqual(generate_metric_list(max_memory_usage_values),
                                 collected_metrics[name]["memory"]["max_mem"][0:5])

            self.assertIn("cpu", collected_metrics[name])
            self.assertIn("cur_cpu", collected_metrics[name]["cpu"])
            self.assertEqual(num_summarization_values, len(collected_metrics[name]["cpu"]["cur_cpu"]))
            self.assertListEqual(generate_metric_list(cpu_percent_values),
                                 collected_metrics[name]["cpu"]["cur_cpu"][0:5])

    def test_cgroup_tracking(self, *args):
        with patch("azurelinuxagent.common.cgroup.CpuCgroup.initialize_cpu_usage") as patch_initialize_cpu_usage:
            num_extensions = 5
            num_controllers = 2
            for i in range(num_extensions):
                dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

                dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                    "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

            for i in range(num_extensions):
                self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
                self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

            self.assertEqual(num_extensions * num_controllers, len(CGroupsTelemetry._tracked))
            self.assertEqual(num_extensions, patch_initialize_cpu_usage.call_count)

    def test_cgroup_pruning(self, *args):
        num_extensions = 5
        num_controllers = 2
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertEqual(num_extensions * num_controllers, len(CGroupsTelemetry._tracked))

        CGroupsTelemetry.prune_all_tracked()

        for i in range(num_extensions):
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertEqual(0, len(CGroupsTelemetry._tracked))

    def test_cgroup_is_tracked(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory", "dummy_extension_{0}".
                                                format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_cpu_dummy_path"))
        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_memory_dummy_path"))

    def test_process_cgroup_metric_with_incorrect_cgroups_mounted(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                patch_get_cpu_usage.side_effect = Exception("File not found")
                patch_get_memory_usage.side_effect = Exception("File not found")

                for data_count in range(1, 10):
                    metrics = CGroupsTelemetry.poll_all_tracked()
                    self.assertEqual(len(metrics), 0)

                self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)

                collected_metrics = {}
                for name, cgroup_metrics in CGroupsTelemetry._cgroup_metrics.items():
                    collected_metrics[name] = CGroupsTelemetry._process_cgroup_metric(cgroup_metrics)
                    self.assertEqual(collected_metrics[name], {})  # empty

    def test_process_cgroup_metric_with_no_memory_cgroup_mounted(self, *args):
        num_extensions = 5

        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                    patch_is_active.return_value = True
                    patch_get_memory_usage.side_effect = Exception("File not found")

                    current_cpu = 30
                    patch_get_cpu_usage.return_value = current_cpu

                    poll_count = 1

                    for data_count in range(poll_count, 10):
                        metrics = CGroupsTelemetry.poll_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        self._assert_cgroup_metrics_equal(cpu_usage=[current_cpu] * data_count, memory_usage=[], max_memory_usage=[])
                        self.assertEqual(len(metrics), num_extensions * 1)  # Only CPU populated
                        self._assert_cgroup_polling_metrics_equal(metrics, current_cpu, 0, 0)

                    CGroupsTelemetry.report_all_tracked()

                    self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                    self._assert_cgroup_metrics_equal([], [], [])

    def test_process_cgroup_metric_with_no_cpu_cgroup_mounted(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        patch_get_cpu_usage.side_effect = Exception("File not found")

                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        poll_count = 1

                        for data_count in range(poll_count, 10):
                            metrics = CGroupsTelemetry.poll_all_tracked()
                            self.assertEqual(len(CGroupsTelemetry._cgroup_metrics), num_extensions)
                            self._assert_cgroup_metrics_equal(
                                cpu_usage=[],
                                memory_usage=[current_memory] * data_count,
                                max_memory_usage=[current_max_memory] * data_count)
                            # Memory is only populated, CPU is not. Thus 2 metrics per cgroup.
                            self.assertEqual(len(metrics), num_extensions * 2)
                            self._assert_cgroup_polling_metrics_equal(metrics, 0, current_memory, current_max_memory)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(len(CGroupsTelemetry._cgroup_metrics), num_extensions)
                        self._assert_cgroup_metrics_equal([], [], [])

    @patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage", side_effect=raise_ioerror)
    @patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage", side_effect=raise_ioerror)
    def test_extension_telemetry_not_sent_for_empty_perf_metrics(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i),
                                                "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry._process_cgroup_metric") as \
                patch_process_cgroup_metric:
            with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:

                patch_is_active.return_value = False
                patch_process_cgroup_metric.return_value = {}
                poll_count = 1

                for data_count in range(poll_count, 10):
                    metrics = CGroupsTelemetry.poll_all_tracked()
                    self.assertEqual(0, len(metrics))

                collected_metrics = CGroupsTelemetry.report_all_tracked()
                self.assertEqual(0, len(collected_metrics))

    @skip_if_predicate_true(lambda: True, "Skipping this test currently: We need two different tests - one for "
                                  "FileSystemCgroupAPI based test and one for SystemDCgroupAPI based test. @vrdmr will "
                                  "be splitting this test in subsequent PRs")
    @skip_if_predicate_false(are_cgroups_enabled, "Does not run when Cgroups are not enabled")
    @skip_if_predicate_true(is_trusty_in_travis, "Does not run on Trusty in Travis")
    @attr('requires_sudo')
    @patch("azurelinuxagent.common.cgroupconfigurator.get_osutil", return_value=DefaultOSUtil())
    @patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False)
    def test_telemetry_with_tracked_cgroup(self, *_):
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        CGroupConfigurator._instance = None

        max_num_polls = 30
        time_to_wait = 3
        extn_name = "foobar-1.0.0"
        num_summarization_values = 7

        cgs = make_new_cgroup(extn_name)
        self.assertEqual(len(cgs), 2)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = "1.0.0"
        self.ext_handler = ExtHandler(name='foobar')
        self.ext_handler.properties = ext_handler_properties
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=self.ext_handler, protocol=None)

        command = self.create_script("keep_cpu_busy_and_consume_memory_for_5_seconds", '''
nohup python -c "import time

for i in range(5):
    x = [1, 2, 3, 4, 5] * (i * 1000)
    time.sleep({0})
    x *= 0
    print('Test loop')" &
'''.format(time_to_wait))

        self.log_dir = os.path.join(self.tmp_dir, "log")

        with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir) as \
                patch_get_base_dir:
            with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir) as \
                    patch_get_log_dir:
                self.ext_handler_instance.launch_command(command)

        self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(
            BASE_CGROUPS, "cpu", "walinuxagent.extensions", "foobar_1.0.0")))
        self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(
            BASE_CGROUPS, "memory", "walinuxagent.extensions", "foobar_1.0.0")))

        for i in range(max_num_polls):
            CGroupsTelemetry.poll_all_tracked()
            time.sleep(0.5)

        collected_metrics = CGroupsTelemetry.report_all_tracked()

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

        for i in range(5):
            self.assertGreater(collected_metrics[extn_name]["memory"]["cur_mem"][i], 0)
            self.assertGreater(collected_metrics[extn_name]["memory"]["max_mem"][i], 0)
            self.assertGreaterEqual(collected_metrics[extn_name]["cpu"]["cur_cpu"][i], 0)
            # Equal because CPU could be zero for minimum value.


class TestMetric(AgentTestCase):
    def test_empty_metrics(self):
        test_metric = Metric()
        self.assertEqual("None", test_metric.first_poll_time())
        self.assertEqual("None", test_metric.last_poll_time())
        self.assertEqual(0, test_metric.count())
        self.assertEqual(None, test_metric.median())
        self.assertEqual(None, test_metric.max())
        self.assertEqual(None, test_metric.min())
        self.assertEqual(None, test_metric.average())

    def test_metrics(self):
        num_polls = 10

        test_values = [random.randint(0, 100) for _ in range(num_polls)]

        test_metric = Metric()
        for value in test_values:
            test_metric.append(value)

        self.assertListEqual(generate_metric_list(test_values), [test_metric.average(), test_metric.min(),
                                                                 test_metric.max(), test_metric.median(),
                                                                 test_metric.count()])

        test_metric.clear()
        self.assertEqual("None", test_metric.first_poll_time())
        self.assertEqual("None", test_metric.last_poll_time())
        self.assertEqual(0, test_metric.count())
        self.assertEqual(None, test_metric.median())
        self.assertEqual(None, test_metric.max())
        self.assertEqual(None, test_metric.min())
        self.assertEqual(None, test_metric.average())
