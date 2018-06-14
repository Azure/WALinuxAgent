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

from azurelinuxagent.common.cgroups import CGroupsTelemetry, CGroups, CGroupsException, BASE_CGROUPS, Cpu, Memory
from tests.tools import *

import os
import random
import time


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):
        waste += random.random()
    return waste


def make_self_cgroups():
    """
    Build a CGroups object for the cgroup to which this process already belongs

    :return: CGroups containing this process
    :rtype: CGroups
    """
    def path_maker(hierarchy, __):
        suffix = CGroups.get_my_cgroup_path(CGroups.get_hierarchy_id('cpu'))
        return os.path.join(BASE_CGROUPS, hierarchy, suffix)

    return CGroups("inplace", path_maker)


def make_root_cgroups():
    """
    Build a CGroups object for the topmost cgroup

    :return: CGroups for most-encompassing cgroup
    :rtype: CGroups
    """
    def path_maker(hierarchy, _):
        return os.path.join(BASE_CGROUPS, hierarchy)

    return CGroups("root", path_maker)


def i_am_root():
    return os.geteuid() == 0


@skip_if_predicate_false(CGroups.enabled, "CGroups not supported in this environment")
class TestCGroups(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        CGroups.setup(True)
        super(AgentTestCase, cls).setUpClass()

    def test_cgroup_utilities(self):
        """
        Test utilities for querying cgroup metadata
        """
        cpu_id = CGroups.get_hierarchy_id('cpu')
        self.assertGreater(int(cpu_id), 0)
        memory_id = CGroups.get_hierarchy_id('memory')
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
        cpu = Cpu(ct)
        self.assertGreater(cpu.current_system_cpu, 0)

        consume_cpu_time()  # Eat some CPU
        cpu.update()

        self.assertGreater(cpu.current_cpu_total, cpu.previous_cpu_total)
        self.assertGreater(cpu.current_system_cpu, cpu.previous_system_cpu)

        percent_used = cpu.get_cpu_percent()
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
            cpu = Cpu(ct)
            self.assertLess(cpu.current_cpu_total, cpu.current_system_cpu)

            consume_cpu_time()  # Eat some CPU
            time.sleep(1)       # Generate some idle time
            cpu.update()
            self.assertLess(cpu.current_cpu_total, cpu.current_system_cpu)

    def exercise_telemetry_instantiation(self, test_cgroup):
        test_extension_name = test_cgroup.name
        CGroupsTelemetry.track_cgroup(test_cgroup)
        self.assertIn('cpu', test_cgroup.cgroups)
        self.assertIn('memory', test_cgroup.cgroups)
        self.assertTrue(CGroupsTelemetry.is_tracked(test_extension_name))
        consume_cpu_time()
        time.sleep(1)
        metrics = CGroupsTelemetry.collect_all_tracked()
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

    @skip_if_predicate_false(i_am_root, "Test does not run when non-root")
    def test_telemetry_instantiation_as_superuser(self):
        """
        Tracking a new cgroup for an extension; collect all metrics.
        """
        # Record initial state
        initial_cgroup = make_self_cgroups()

        # Put the process into a different cgroup, consume some resources, ensure we see them end-to-end
        test_cgroup = CGroups.for_extension("agent_unittest")
        test_cgroup.add(os.getpid())
        self.assertNotEqual(initial_cgroup.cgroups['cpu'], test_cgroup.cgroups['cpu'])
        self.assertNotEqual(initial_cgroup.cgroups['memory'], test_cgroup.cgroups['memory'])

        self.exercise_telemetry_instantiation(test_cgroup)

        # Restore initial state
        CGroupsTelemetry.stop_tracking("agent_unittest")
        initial_cgroup.add(os.getpid())

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    def test_telemetry_instantiation_as_normal_user(self):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        self.exercise_telemetry_instantiation(make_self_cgroups())

    def test_cpu_telemetry(self):
        """
        Test Cpu telemetry class
        """
        cg = make_self_cgroups()
        self.assertIn('cpu', cg.cgroups)
        ct = CGroupsTelemetry('test', cg)
        self.assertIs(cg, ct.cgroup)
        cpu = Cpu(ct)
        self.assertIs(cg, cpu.cgt.cgroup)
        ticks_before = cpu.current_cpu_total
        consume_cpu_time()
        time.sleep(1)
        cpu.update()
        ticks_after = cpu.current_cpu_total
        self.assertGreater(ticks_after, ticks_before)
        p2 = cpu.get_cpu_percent()
        self.assertGreater(p2, 0)
        # when running under PyCharm, this is often > 100
        # on a multi-core machine
        self.assertLess(p2, 200)

    def test_memory_telemetry(self):
        """
        Test Memory telemetry class
        """
        cg = make_self_cgroups()
        raw_usage_file_contents = cg.get_file_contents('memory', 'memory.usage_in_bytes')
        self.assertIsNotNone(raw_usage_file_contents)
        self.assertGreater(len(raw_usage_file_contents), 0)
        self.assertIn('memory', cg.cgroups)
        ct = CGroupsTelemetry('test', cg)
        self.assertIs(cg, ct.cgroup)
        memory = Memory(ct)
        usage_in_bytes = memory.get_memory_usage()
        self.assertGreater(usage_in_bytes, 100000)

    def test_format_memory_value(self):
        """
        Test formatting of memory amounts into human-readable units
        """
        self.assertEqual(-1, CGroups._format_memory_value('bytes', None))
        self.assertEqual(2048, CGroups._format_memory_value('kilobytes', 2))
        self.assertEqual(0, CGroups._format_memory_value('kilobytes', 0))
        self.assertEqual(2048000, CGroups._format_memory_value('kilobytes', 2000))
        self.assertEqual(2048*1024, CGroups._format_memory_value('megabytes', 2))
        self.assertEqual((1024 + 512) * 1024 * 1024, CGroups._format_memory_value('gigabytes', 1.5))
        self.assertRaises(CGroupsException, CGroups._format_memory_value, 'KiloBytes', 1)
