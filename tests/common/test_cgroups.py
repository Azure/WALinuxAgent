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
# Requires Python 2.4+ and Openssl 1.0+
#

from __future__ import print_function

import random

from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.version import AGENT_NAME
from tests.tools import *


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):
        waste += random.random()
    return waste


def make_self_cgroups():
    """
    Build a CGroups object for the cgroup to which this process already belongs

    :return: CGroups containing this process
    :rtype: CGroupConfigurator
    """

    def path_maker(hierarchy, __):
        suffix = CGroupConfigurator._get_current_process_cgroup_path(CGroupConfigurator.get_hierarchy_id('cpu'))
        return os.path.join(BASE_CGROUPS, hierarchy, suffix)

    return CGroupConfigurator("inplace", path_maker)


def make_root_cgroups():
    """
    Build a CGroups object for the topmost cgroup

    :return: CGroups for most-encompassing cgroup
    :rtype: CGroupConfigurator
    """

    def path_maker(hierarchy, _):
        return os.path.join(BASE_CGROUPS, hierarchy)

    return CGroupConfigurator("root", path_maker)


def i_am_root():
    return os.geteuid() == 0


@skip_if_predicate_false(lambda: False, "TODO: Need new unit tests")
class TestCGroups(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        CGroupConfigurator.get_instance()
        super(AgentTestCase, cls).setUpClass()

    def test_cgroup_utilities(self):
        """
        Test utilities for querying cgroup metadata
        """
        cpu_id = CGroupConfigurator.get_hierarchy_id('cpu')
        self.assertGreater(int(cpu_id), 0)
        memory_id = CGroupConfigurator.get_hierarchy_id('memory')
        self.assertGreater(int(memory_id), 0)
        self.assertNotEqual(cpu_id, memory_id)

    def test_telemetry_inplace(self):
        """
        Test raw measures and basic statistics for the cgroup in which this process is currently running.
        """
        cg = make_self_cgroups()
        self.assertIn('cpu', cg.cgroups)
        self.assertIn('memory', cg.cgroups)
        ct = CGroupsTelemetry("test", cg)
        cpu = CpuCgroup(ct)
        self.assertGreater(cpu._current_system_cpu, 0)

        consume_cpu_time()  # Eat some CPU
        cpu._update_cpu_data()

        self.assertGreater(cpu._current_cpu_total, cpu._previous_cpu_total)
        self.assertGreater(cpu._current_system_cpu, cpu._previous_system_cpu)

        percent_used = cpu._get_cpu_percent()
        self.assertGreater(percent_used, 0)

    def test_telemetry_in_place_leaf_cgroup(self):
        """
        Ensure this leaf (i.e. not root of cgroup tree) cgroup has distinct metrics from the root cgroup.
        """
        # Does nothing on systems where the default cgroup for a randomly-created process (like this test invocation)
        # is the root cgroup.
        cg = make_self_cgroups()
        root = make_root_cgroups()
        if cg.cgroups['cpu'] != root.cgroups['cpu']:
            ct = CGroupsTelemetry("test", cg)
            cpu = CpuCgroup(ct)
            self.assertLess(cpu._current_cpu_total, cpu._current_system_cpu)

            consume_cpu_time()  # Eat some CPU
            time.sleep(1)  # Generate some idle time
            cpu._update_cpu_data()
            self.assertLess(cpu._current_cpu_total, cpu._current_system_cpu)

    def exercise_telemetry_instantiation(self, test_cgroup):
        test_extension_name = test_cgroup.name
        CGroupsTelemetry.track_cgroup(test_cgroup)
        self.assertIn('cpu', test_cgroup.cgroups)
        self.assertIn('memory', test_cgroup.cgroups)
        self.assertTrue(CGroupsTelemetry.is_tracked(test_extension_name))
        consume_cpu_time()
        time.sleep(1)
        metrics, limits = CGroupsTelemetry.report_all_tracked()
        my_metrics = metrics[test_extension_name]
        self.assertEqual(len(my_metrics), 2)
        for item in my_metrics:
            metric_family, metric_name, metric_value = item
            if metric_family == "Process":
                self.assertEqual(metric_name, "% Processor Time")
                self.assertGreater(metric_value, 0.0)
            elif metric_family == "Memory":
                self.assertEqual(metric_name, "Total Memory Usage")
                self.assertGreater(metric_value, 100000)
            else:
                self.fail("Unknown metric {0}/{1} value {2}".format(metric_family, metric_name, metric_value))

        my_limits = limits[test_extension_name]
        self.assertIsInstance(my_limits, CGroupsLimits, msg="is not the correct instance")
        self.assertGreater(my_limits.cpu_limit, 0.0)
        self.assertGreater(my_limits.memory_limit, 0.0)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores", return_value=1)
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat")
    def test_get_cpu_usage(self, patch_get_proc_stat, *args):
        patch_get_proc_stat.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat"))
        test_cpu_cg = CpuCgroup("test_extension", os.path.join(data_dir, "cgroups", "cpu_mount"))

        # Put the process into a different cgroup, consume some resources, ensure we see them end-to-end
        test_cgroup = CGroupConfigurator.for_extension("agent_unittest")
        test_cgroup.add(os.getpid())
        self.assertNotEqual(initial_cgroup.cgroups['cpu'], test_cgroup.cgroups['cpu'])
        self.assertNotEqual(initial_cgroup.cgroups['memory'], test_cgroup.cgroups['memory'])

        cpu_usage = test_cpu_cg.get_cpu_usage()

        self.assertEqual(5.114, cpu_usage)

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    def test_telemetry_instantiation_as_normal_user(self):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        self.exercise_telemetry_instantiation(make_self_cgroups())

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    @patch("azurelinuxagent.common.conf.get_cgroups_enforce_limits")
    @patch("azurelinuxagent.common.cgroupconfigurator.CGroupConfigurator.set_cpu_limit")
    @patch("azurelinuxagent.common.cgroupconfigurator.CGroupConfigurator.set_memory_limit")
    def test_telemetry_instantiation_as_normal_user_with_limits(self, mock_get_cgroups_enforce_limits,
                                                                mock_set_cpu_limit,
                                                                mock_set_memory_limit):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        mock_get_cgroups_enforce_limits.return_value = True

        cg = make_self_cgroups()
        cg.set_limits()
        self.exercise_telemetry_instantiation(cg)

    def test_cpu_telemetry(self):
        """
        Test Cpu telemetry class
        """
        cg = make_self_cgroups()
        self.assertIn('cpu', cg.cgroups)
        ct = CGroupsTelemetry('test', cg)
        self.assertIs(cg, ct.cgroup)
        cpu = CpuCgroup(ct)
        self.assertIs(cg, cpu.cgt.cgroup)
        ticks_before = cpu._current_cpu_total
        consume_cpu_time()
        time.sleep(1)
        cpu._update_cpu_data()
        ticks_after = cpu._current_cpu_total
        self.assertGreater(ticks_after, ticks_before)
        p2 = cpu._get_cpu_percent()
        self.assertGreater(p2, 0)
        # when running under PyCharm, this is often > 100
        # on a multi-core machine
        self.assertLess(p2, 200)

    def test_get_metrics(self):
        test_mem_cg = MemoryCgroup("test_extension", os.path.join(data_dir, "cgroups", "memory_mount"))

        memory_usage = test_mem_cg.get_memory_usage()
        self.assertEqual(100000, memory_usage)

        max_memory_usage = test_mem_cg.get_max_memory_usage()
        self.assertEqual(1000000, max_memory_usage)

    def test_get_metrics_when_files_not_present(self):
        test_mem_cg = MemoryCgroup("test_extension", os.path.join(data_dir, "cgroups"))

        memory_usage = test_mem_cg.get_memory_usage()
        self.assertEqual(0, memory_usage)

        max_memory_usage = test_mem_cg.get_max_memory_usage()
        self.assertEqual(0, max_memory_usage)