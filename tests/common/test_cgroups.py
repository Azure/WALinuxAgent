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

import mock

from azurelinuxagent.common.cgroups import CGroupsTelemetry, CGroups, CGroupsException
from tests.tools import *

import os
import random
import time


def waste_time():
    waste = 0
    for x in range(1,100000):
        waste += random.random()
    return waste


class TestCGroups(AgentTestCase):
    @patch("os.mkdir")
    @patch("azurelinuxagent.common.cgroups.CGroups.create_user_cgroups")
    def test_cgroups_telemetry_inplace(self, _, __):
        """
        Test raw measures and basic statistics for the cgroup in which this process is currently running.
        """
        cpu_hierarchy_id = CGroups.get_hierarchy_id('cpu')
        self.assertTrue(cpu_hierarchy_id != '')
        in_root_cgroup = True
        cgroup_path = CGroups.get_my_cgroup_path(cpu_hierarchy_id)
        if cgroup_path.startswith("/"):
            cgroup_path.lstrip("/")
            in_root_cgroup = False
        ct = CGroupsTelemetry(cgroup_path)
        self.assertTrue(ct.cpu_count > 0)
        self.assertTrue(ct.current_system_cpu > 0)
        self.assertTrue(ct.current_cpu_total > 0)
        if not in_root_cgroup:
            # If I'm not in the root cgroup, then make sure I'm measuring my group distinctly from the whole system
            self.assertTrue(ct.current_cpu_total < ct.current_system_cpu)
        waste_time()    # Eat some CPU
        time.sleep(1)   # Generate some idle time
        percent_used = ct.get_cpu_percent()
        self.assertTrue(ct.current_cpu_total > ct.previous_cpu_total)
        self.assertTrue(ct.current_system_cpu > ct.previous_system_cpu)
        self.assertTrue(percent_used > 0)

    @patch("os.mkdir")
    @patch("azurelinuxagent.common.cgroups.CGroups.create_user_cgroups")
    @patch("azurelinuxagent.common.cgroups.CGroups._get_cgroup_file",
           return_value="/sys/fs/cgroup/cpu/cpuacct.stat")
    def test_cgroups_telemetry_instantiation(self, _, __, ___):
        ct = CGroupsTelemetry('test')
        self.assertTrue(ct.cpu_count > 0)
        self.assertTrue(ct.current_system_cpu > 0)
        self.assertTrue(ct.current_cpu_total > 0)

    @patch("os.mkdir")
    @patch("azurelinuxagent.common.cgroups.CGroups.create_user_cgroups")
    @patch("azurelinuxagent.common.cgroups.CGroups._get_cgroup_file",
           return_value="/sys/fs/cgroup/cpu/cpuacct.stat")
    def test_cgroups_telemetry_cpu(self, _, __, ___):
        ct = CGroupsTelemetry('test')
        p1 = ct.get_cpu_percent()
        p2 = ct.get_cpu_percent()
        self.assertTrue(p1 > 0)
        self.assertTrue(p2 > 0)
        self.assertTrue(p2 != p1)

    def test_format_memory_value(self):
        self.assertTrue(-1 == CGroups._format_memory_value('bytes', None))
        self.assertTrue(2048 == CGroups._format_memory_value('kilobytes', 2))
        self.assertTrue(0 == CGroups._format_memory_value('kilobytes', 0))
        self.assertTrue(2048000 == CGroups._format_memory_value('kilobytes', 2000))
        self.assertTrue(2048*1024 == CGroups._format_memory_value('megabytes', 2))
        self.assertTrue(1536 * 1024 * 1024 == CGroups._format_memory_value('gigabytes', 1.5))
        self.assertRaises(CGroupsException, CGroups._format_memory_value, ['KiloBytes', 1])
