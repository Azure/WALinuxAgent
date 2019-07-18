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

from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup, CGroup
from azurelinuxagent.common.exception import CGroupsException
from tests.tools import *


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):
        waste += random.random()
    return waste


def i_am_root():
    return os.geteuid() == 0


class TestCGroup(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        
        self.cgroup_root = tempfile.mkdtemp()
        self.cgroup_cpu_mount = os.path.join(self.cgroup_root, "cpu")
        self.cgroup_memory_mount = os.path.join(self.cgroup_root, "memory")

        shutil.copytree(os.path.join(data_dir, "cgroups", "cpu_mount"), self.cgroup_cpu_mount)
        shutil.copytree(os.path.join(data_dir, "cgroups", "memory_mount"), self.cgroup_memory_mount)

    def tearDown(self):
        AgentTestCase.tearDown(self)
        fileutil.rm_dirs(self.cgroup_root)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat",
           return_value=fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat")))
    def test_correct_creation(self, patch_get_proc_stat):
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

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat",
           return_value=fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat")))
    def test_is_active(self, patch_get_proc_stat):
        test_cgroup = CGroup.create(self.cgroup_cpu_mount, "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        with open(os.path.join(self.cgroup_cpu_mount, "tasks"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_cgroup.is_active())

        test_cgroup = CGroup.create(self.cgroup_memory_mount, "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        with open(os.path.join(self.cgroup_memory_mount, "tasks"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_cgroup.is_active())

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat",
           return_value=fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat")))
    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_file_not_present(self, patch_periodic_warn, patch_get_proc_stat):

        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "not_cpu_mount"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        test_cgroup = CGroup.create(os.path.join(data_dir, "cgroups", "not_memory_mount"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat",
           return_value=fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat")))
    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_incorrect_file(self, patch_periodic_warn, patch_get_proc_stat):
        test_cgroup = CGroup.create(os.path.join(self.cgroup_cpu_mount, "tasks"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())
        self.assertEqual(1, patch_periodic_warn.call_count)

        test_cgroup = CGroup.create(os.path.join(self.cgroup_memory_mount, "tasks"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())
        self.assertEqual(2, patch_periodic_warn.call_count)


@patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat",
       return_value=fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_stat")))
class TestCpuCgroup(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.cgroup_root = tempfile.mkdtemp()
        self.cgroup_cpu_mount = os.path.join(self.cgroup_root, "cpu")
        shutil.copytree(os.path.join(data_dir, "cgroups", "cpu_mount"), self.cgroup_cpu_mount)

    def tearDown(self):
        AgentTestCase.tearDown(self)
        fileutil.rm_dirs(self.cgroup_root)

    def test_cpu_cgroup_create(self, patch_get_proc_stat):
        test_cpu_cg = CpuCgroup("test_extension", "dummy_path")

        self.assertEqual(398488, test_cpu_cg._current_system_cpu)
        self.assertEqual(0, test_cpu_cg._current_cpu_total)
        self.assertEqual(0, test_cpu_cg._previous_cpu_total)
        self.assertEqual(0, test_cpu_cg._previous_system_cpu)

        self.assertEqual("cpu", test_cpu_cg.controller)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores", return_value=1)
    def test_collect(self, patch_get_processor_cores, patch_get_proc_stat, *args):
        test_cpu_cg = CpuCgroup("test_extension", self.cgroup_cpu_mount)

        # Mocking CPU consumption
        patch_get_proc_stat.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups",
                                                                           "dummy_proc_stat_updated"))

        collected_metric = test_cpu_cg.collect()[0]

        self.assertEqual("cpu", collected_metric.controller)
        self.assertEqual("% Processor Time", collected_metric.metric_name)
        self.assertEqual(5.114, collected_metric.value)

    def test_get_current_cpu_total_exception_handling(self, *args):
        test_cpu_cg = CpuCgroup("test_extension", "dummy_path")
        self.assertRaises(IOError, test_cpu_cg._get_current_cpu_total)

        # Trying to raise ERRNO 20.
        test_cpu_cg = CpuCgroup("test_extension", os.path.join(self.cgroup_cpu_mount, "cpuacct.stat"))
        self.assertRaises(CGroupsException, test_cpu_cg._get_current_cpu_total)


class TestMemoryCgroup(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.cgroup_root = tempfile.mkdtemp()
        self.cgroup_memory_mount = os.path.join(self.cgroup_root, "memory")
        shutil.copytree(os.path.join(data_dir, "cgroups", "memory_mount"), self.cgroup_memory_mount)

    def tearDown(self):
        AgentTestCase.tearDown(self)
        fileutil.rm_dirs(self.cgroup_root)

    def test_memory_cgroup_create(self):
        test_mem_cg = MemoryCgroup("test_extension", self.cgroup_memory_mount)
        self.assertEqual("memory", test_mem_cg.controller)

    def test_collect(self):
        test_mem_cg = MemoryCgroup("test_extension", self.cgroup_memory_mount)
        metrics = test_mem_cg.collect()

        current_mem_collected_metric = metrics[0]

        self.assertEqual("memory", current_mem_collected_metric.controller)
        self.assertEqual("Total Memory Usage", current_mem_collected_metric.metric_name)
        self.assertEqual(100000, current_mem_collected_metric.value)

        max_mem_collected_metric = metrics[1]

        self.assertEqual("memory", max_mem_collected_metric.controller)
        self.assertEqual("Max Memory Usage", max_mem_collected_metric.metric_name)
        self.assertEqual(1000000, max_mem_collected_metric.value)

        metrics = test_mem_cg.collect()

        # Making sure that the max is reset to 0.
        max_mem_collected_metric = metrics[1]

        self.assertEqual("memory", max_mem_collected_metric.controller)
        self.assertEqual("Max Memory Usage", max_mem_collected_metric.metric_name)
        self.assertEqual(0, max_mem_collected_metric.value)

    def test_collect_when_files_not_present(self):
        test_mem_cg = MemoryCgroup("test_extension", self.cgroup_root)
        metrics = test_mem_cg.collect()

        current_mem_collected_metric = metrics[0]

        self.assertEqual("memory", current_mem_collected_metric.controller)
        self.assertEqual("Total Memory Usage", current_mem_collected_metric.metric_name)
        self.assertEqual(0, current_mem_collected_metric.value)

        max_mem_collected_metric = metrics[1]

        self.assertEqual("memory", max_mem_collected_metric.controller)
        self.assertEqual("Max Memory Usage", max_mem_collected_metric.metric_name)
        self.assertEqual(0, max_mem_collected_metric.value)
