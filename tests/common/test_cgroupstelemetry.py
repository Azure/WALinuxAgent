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

import os
import random
import stat
import time

from mock import patch

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry, Metric
from azurelinuxagent.common.protocol.restapi import ExtHandlerProperties, ExtHandler
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance
from tests.common.test_cgroupapi import i_am_root
from tests.tools import AgentTestCase, skip_if_predicate_false


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
    def setUp(self):
        AgentTestCase.setUp(self)
        CGroupsTelemetry.cleanup()

    @patch("azurelinuxagent.common.cgroup.CpuCgroup._get_current_cpu_total")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_cpu_ticks_since_boot")
    def test_telemetry_polling_with_active_cgroups(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_percent.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        poll_count = 1

                        for data_count in range(poll_count, 10):
                            CGroupsTelemetry.poll_all_tracked()
                            self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                            for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                                current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                                self.assertEqual(len(current_memory_usage._data), data_count)
                                self.assertListEqual(current_memory_usage._data, [current_memory] * data_count)
                                self.assertEqual(len(max_memory_levels._data), data_count)
                                self.assertListEqual(max_memory_levels._data, [current_max_memory] * data_count)
                                self.assertEqual(len(current_cpu_usage._data), data_count)
                                self.assertListEqual(current_cpu_usage._data, [current_cpu] * data_count)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), 0)
                            self.assertEqual(len(max_memory_levels._data), 0)
                            self.assertEqual(len(current_cpu_usage._data), 0)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_percent.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        poll_count = 1

                        for data_count in range(poll_count, 10):
                            CGroupsTelemetry.poll_all_tracked()
                            self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                            for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                                current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                                self.assertEqual(len(current_memory_usage._data), data_count)
                                self.assertListEqual(current_memory_usage._data, [current_memory] * data_count)
                                self.assertEqual(len(max_memory_levels._data), data_count)
                                self.assertListEqual(max_memory_levels._data, [current_max_memory] * data_count)
                                self.assertEqual(len(current_cpu_usage._data), data_count)
                                self.assertListEqual(current_cpu_usage._data, [current_cpu] * data_count)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)
                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), 0)
                            self.assertEqual(len(max_memory_levels._data), 0)
                            self.assertEqual(len(current_cpu_usage._data), 0)

    @patch("azurelinuxagent.common.cgroup.CpuCgroup._get_current_cpu_total")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_cpu_ticks_since_boot")
    def test_telemetry_polling_with_inactive_cgroups(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = False

                        no_extensions_expected = 0
                        data_count = 1
                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_percent.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

                        CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)

                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), data_count)
                            self.assertListEqual(current_memory_usage._data, [current_memory] * data_count)
                            self.assertEqual(len(max_memory_levels._data), data_count)
                            self.assertListEqual(max_memory_levels._data, [current_max_memory] * data_count)
                            self.assertEqual(len(current_cpu_usage._data), data_count)
                            self.assertListEqual(current_cpu_usage._data, [current_cpu] * data_count)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), no_extensions_expected)
                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), 0)
                            self.assertEqual(len(max_memory_levels._data), 0)
                            self.assertEqual(len(current_cpu_usage._data), 0)

    @patch("azurelinuxagent.common.cgroup.CpuCgroup._get_current_cpu_total")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_cpu_ticks_since_boot")
    def test_telemetry_polling_with_changing_cgroups_state(self, *args):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        patch_is_active.return_value = True

                        no_extensions_expected = 0
                        expected_data_count = 2

                        current_cpu = 30
                        current_memory = 209715200
                        current_max_memory = 471859200

                        patch_get_cpu_percent.return_value = current_cpu
                        patch_get_memory_usage.return_value = current_memory  # example 200 MB
                        patch_get_memory_max_usage.return_value = current_max_memory  # example 450 MB

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

                        CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
                            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)

                        patch_is_active.return_value = False
                        CGroupsTelemetry.poll_all_tracked()

                        for i in range(num_extensions):
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
                            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), num_extensions)

                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), expected_data_count)
                            self.assertListEqual(current_memory_usage._data, [current_memory] * expected_data_count)
                            self.assertEqual(len(max_memory_levels._data), expected_data_count)
                            self.assertListEqual(max_memory_levels._data, [current_max_memory] * expected_data_count)
                            self.assertEqual(len(current_cpu_usage._data), expected_data_count)
                            self.assertListEqual(current_cpu_usage._data, [current_cpu] * expected_data_count)

                        CGroupsTelemetry.report_all_tracked()

                        self.assertEqual(CGroupsTelemetry._cgroup_metrics.__len__(), no_extensions_expected)
                        for cgroup_name, cgroup_metric in CGroupsTelemetry._cgroup_metrics.items():
                            current_memory_usage, max_memory_levels, current_cpu_usage = cgroup_metric.get_metrics()
                            self.assertEqual(len(current_memory_usage._data), 0)
                            self.assertEqual(len(max_memory_levels._data), 0)
                            self.assertEqual(len(current_cpu_usage._data), 0)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_cpu_ticks_since_boot")
    @patch("azurelinuxagent.common.cgroup.CpuCgroup._get_current_cpu_total")
    @patch("azurelinuxagent.common.cgroup.CpuCgroup._update_cpu_data")
    def test_telemetry_calculations(self, *args):
        num_polls = 10
        num_extensions = 1
        num_summarization_values = 7

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        for i in range(num_polls):
                            patch_is_active.return_value = True
                            patch_get_cpu_percent.return_value = cpu_percent_values[i]
                            patch_get_memory_usage.return_value = memory_usage_values[i]  # example 200 MB
                            patch_get_memory_max_usage.return_value = max_memory_usage_values[i]  # example 450 MB
                            CGroupsTelemetry.poll_all_tracked()

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

    def test_cgroup_tracking(self):
        num_extensions = 5
        num_controllers = 2
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

        self.assertEqual(num_extensions * num_controllers, len(CGroupsTelemetry._tracked))

    def test_cgroup_pruning(self):
        num_extensions = 5
        num_controllers = 2
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

        self.assertEqual(num_extensions * num_controllers, len(CGroupsTelemetry._tracked))

        CGroupsTelemetry.prune_all_tracked()

        for i in range(num_extensions):
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "cpu"))
            self.assertFalse(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), "memory"))

        self.assertEqual(0, len(CGroupsTelemetry._tracked))

    def test_cgroup_is_tracked(self):
        num_extensions = 5
        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_path", "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_path", "memory", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), 'cpu'))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_extension_{0}".format(i), 'memory'))

        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_dummy_extension_{0}".format(i), 'cpu'))
        self.assertFalse(CGroupsTelemetry.is_tracked("not_present_dummy_extension_{0}".format(i), 'memory'))

    @skip_if_predicate_false(i_am_root, "This test will only run as root")
    @skip_if_predicate_false(CGroupConfigurator.is_cgroups_supported, "CGroups not supported in this environment")
    def test_telemetry_with_tracked_cgroup(self):
        max_num_polls = 30
        time_to_wait = 3
        extn_name = "foobar-1.0.0"

        cgs = make_new_cgroup(extn_name)
        self.assertEqual(len(cgs), 2)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = "1.0.0"
        self.ext_handler = ExtHandler(name='foobar')
        self.ext_handler.properties = ext_handler_properties
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=self.ext_handler, protocol=None)

        command = self._create_script("keep_cpu_busy_and_consume_memory_for_5_seconds", '''
nohup python -c "import time

for i in range(5):
    x = [1, 2, 3, 4, 5] * (i * 1000)
    time.sleep({0})
    x *= 0
    print('Test loop')" &
'''.format(time_to_wait))

        self.log_dir = os.path.join(self.tmp_dir, "log")

        with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir) as patch_get_base_dir:
            with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir) as patch_get_log_dir:
                self.ext_handler_instance.launch_command(command)

        for i in range(max_num_polls):
            CGroupsTelemetry.poll_all_tracked()
            time.sleep(0.5)

        collected_metrics = CGroupsTelemetry.report_all_tracked()
        print(collected_metrics)

        self.assertIn("memory", collected_metrics[extn_name])
        self.assertIn("cur_mem", collected_metrics[extn_name]["memory"])
        self.assertIn("max_mem", collected_metrics[extn_name]["memory"])
        self.assertGreater(len(collected_metrics[extn_name]["memory"]["cur_mem"]), 0)
        self.assertGreater(len(collected_metrics[extn_name]["memory"]["max_mem"]), 0)

        self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][5], str)
        self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][6], str)
        self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][5], str)
        self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][6], str)

        self.assertIn("cpu", collected_metrics[extn_name])
        self.assertIn("cur_cpu", collected_metrics[extn_name]["cpu"])
        self.assertGreaterEqual(len(collected_metrics[extn_name]["cpu"]["cur_cpu"]), 0)

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
        # self.assertEqual("None", test_metric.append())

    def test_metrics(self):
        num_polls = 10

        test_values = [random.randint(0, 100) for _ in range(num_polls)]

        test_metric = Metric()
        for value in test_values:
            test_metric.append(value)

        self.assertListEqual(generate_metric_list(test_values), [test_metric.average(), test_metric.min(),
                                                                 test_metric.max(), test_metric.median(),
                                                                 test_metric.count()])
