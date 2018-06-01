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

from azurelinuxagent.common.cgroups import CGroupsTelemetry, CGroups, CGroupsException, BASE_CGROUPS, Cpu
from tests.tools import *

import os
import random
import time


def consume_cpu_time():
    waste = 0
    for x in range(1, 100000):
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


class TestCGroups(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        CGroups.setup()

    def test_cgroups_telemetry_inplace(self):
        """
        Test raw measures and basic statistics for the cgroup in which this process is currently running.
        """
        cg = make_self_cgroups()
        ct = CGroupsTelemetry("test", cg)
        cpu = Cpu(ct)
        self.assertGreater(cpu.current_system_cpu, 0)

        consume_cpu_time()  # Eat some CPU
        time.sleep(1)       # Generate some idle time
        cpu.update()

        self.assertGreater(cpu.current_cpu_total, cpu.previous_cpu_total)
        self.assertGreater(cpu.current_system_cpu, cpu.previous_system_cpu)

        percent_used = cpu.get_cpu_percent()
        self.assertGreater(percent_used, 0)

    def test_cgroups_telemetry_in_place_non_root(self):
        """
        Ensure this (non-root) cgroup has distinct metrics from the root cgroup. Does nothing on systems where the
        default cgroup for a randomly-created process (like this test invocation) is the root cgroup.
        """
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

    def test_cgroups_telemetry_instantiation(self):
        pass

    def test_cgroups_telemetry_cpu(self):
        cg = make_self_cgroups()
        ct = CGroupsTelemetry('test', cg)
        cpu = Cpu(ct)
        ticks_before = cpu.current_cpu_total
        consume_cpu_time()
        cpu.update()
        ticks_after = cpu.current_cpu_total
        p2 = cpu.get_cpu_percent()
        self.assertGreater(p2, 0)
        self.assertLess(p2, 100)
        self.assertGreater(ticks_after, ticks_before)

    def test_format_memory_value(self):
        self.assertEqual(-1, CGroups._format_memory_value('bytes', None))
        self.assertEqual(2048, CGroups._format_memory_value('kilobytes', 2))
        self.assertEqual(0, CGroups._format_memory_value('kilobytes', 0))
        self.assertEqual(2048000, CGroups._format_memory_value('kilobytes', 2000))
        self.assertEqual(2048*1024, CGroups._format_memory_value('megabytes', 2))
        self.assertEqual((1024 + 512) * 1024 * 1024, CGroups._format_memory_value('gigabytes', 1.5))
        self.assertRaises(CGroupsException, CGroups._format_memory_value, 'KiloBytes', 1)
