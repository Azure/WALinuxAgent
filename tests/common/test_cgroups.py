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

import os
import random

from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup, CGroup
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, patch, data_dir


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):
        waste += random.random()
    return waste


class TestCGroup(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

        with open(os.path.join(data_dir, "cgroups", "cpu_mount", "tasks"), mode="wb") as tasks:
            tasks.truncate(0)
        with open(os.path.join(data_dir, "cgroups", "memory_mount", "tasks"), mode="wb") as tasks:
            tasks.truncate(0)

    def test_correct_creation(self):
        test_cgroup = CGroup.create("dummy_path", "cpu", "test_extension")
        self.assertIsInstance(test_cgroup, CpuCgroup)
        self.assertEqual(test_cgroup.controller, "cpu")
        self.assertEqual(test_cgroup.path, "dummy_path")
        self.assertEqual(test_cgroup.name, "test_extension")

        test_cgroup = CGroup.create("dummy_path", "memory", "test_extension")
        self.assertIsInstance(test_cgroup, MemoryCgroup)
        self.assertEqual(test_cgroup.controller, "memory")
        self.assertEqual(test_cgroup.path, "dummy_path")
        self.assertEqual(test_cgroup.name, "test_extension")

    def test_is_active(self):
        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "cpu_mount"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        with open(os.path.join(data_dir, "cgroups", "cpu_mount", "tasks"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_cgroup.is_active())

        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "memory_mount"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        with open(os.path.join(data_dir, "cgroups", "memory_mount", "tasks"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_cgroup.is_active())

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_file_not_present(self, patch_periodic_warn):
        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "not_cpu_mount"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "not_memory_mount"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_incorrect_file(self, patch_periodic_warn):
        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "cpu_mount", "tasks"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())
        self.assertEqual(1, patch_periodic_warn.call_count)

        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "memory_mount", "tasks"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())
        self.assertEqual(2, patch_periodic_warn.call_count)


class TestCpuCgroup(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat")
    def test_cpu_cgroup_create(self, patch_get_proc_stat):
        patch_get_proc_stat.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat"))
        test_cpu_cg = CpuCgroup("test_extension", "dummy_path")

        self.assertEqual(398488, test_cpu_cg._current_system_cpu)
        self.assertEqual(0, test_cpu_cg._current_cpu_total)
        self.assertEqual(0, test_cpu_cg._previous_cpu_total)
        self.assertEqual(0, test_cpu_cg._previous_system_cpu)

        self.assertEqual("cpu", test_cpu_cg.controller)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores", return_value=1)
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat")
    def test_get_cpu_usage(self, patch_get_proc_stat, *args):
        patch_get_proc_stat.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat"))
        test_cpu_cg = CpuCgroup("test_extension", os.path.join(data_dir, "cgroups", "cpu_mount"))

        # Mocking CPU consumption
        patch_get_proc_stat.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups",
                                                                           "dummy_proc_stat_updated"))

        cpu_usage = test_cpu_cg.get_cpu_usage()

        self.assertEqual(5.114, cpu_usage)

    def test_get_current_cpu_total_exception_handling(self):
        test_cpu_cg = CpuCgroup("test_extension", "dummy_path")
        self.assertRaises(IOError, test_cpu_cg._get_current_cpu_total)

        # Trying to raise ERRNO 20.
        test_cpu_cg = CpuCgroup("test_extension", os.path.join(data_dir, "cgroups", "cpu_mount", "cpuacct.stat"))
        self.assertRaises(CGroupsException, test_cpu_cg._get_current_cpu_total)


class TestMemoryCgroup(AgentTestCase):
    def test_memory_cgroup_create(self):
        test_mem_cg = MemoryCgroup("test_extension", os.path.join(data_dir, "cgroups", "memory_mount"))
        self.assertEqual("memory", test_mem_cg.controller)

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