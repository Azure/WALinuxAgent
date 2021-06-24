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

import errno
import os
import random

from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCgroup, CGroup
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, patch, data_dir


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):  # pylint: disable=unused-variable
        waste += random.random()
    return waste


class TestCGroup(AgentTestCase):
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
        test_cgroup = CGroup.create(self.tmp_dir, "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        with open(os.path.join(self.tmp_dir, "tasks"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_cgroup.is_active())

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_file_not_present(self, patch_periodic_warn):
        test_cgroup = CGroup.create(self.tmp_dir, "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        test_cgroup = CGroup.create(os.path.join(self.tmp_dir, "this_cgroup_does_not_exist"), "memory", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())

        self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_incorrect_file(self, patch_periodic_warn):
        open(os.path.join(self.tmp_dir, "tasks"), mode="wb").close()
        test_cgroup = CGroup.create(os.path.join(self.tmp_dir, "tasks"), "cpu", "test_extension")
        self.assertEqual(False, test_cgroup.is_active())
        self.assertEqual(1, patch_periodic_warn.call_count)


class TestCpuCgroup(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        original_read_file = fileutil.read_file

        #
        # Tests that need to mock the contents of /proc/stat or */cpuacct/stat can set this map from
        # the file that needs to be mocked to the mock file (each test starts with an empty map). If
        # an Exception is given instead of a path, the exception is raised
        #
        cls.mock_read_file_map = {}

        def mock_read_file(filepath, **args):
            if filepath in cls.mock_read_file_map:
                mapped_value = cls.mock_read_file_map[filepath]
                if isinstance(mapped_value, Exception):
                    raise mapped_value
                filepath = mapped_value
            return original_read_file(filepath, **args)

        cls.mock_read_file = patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=mock_read_file)
        cls.mock_read_file.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_read_file.stop()
        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)
        TestCpuCgroup.mock_read_file_map.clear()

    def test_initialize_cpu_usage_should_set_current_cpu_usage(self):
        cgroup = CpuCgroup("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t0"),
            os.path.join(cgroup.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "cpuacct.stat_t0")
        }

        cgroup.initialize_cpu_usage()

        self.assertEqual(cgroup._current_cgroup_cpu, 63763)  # pylint: disable=protected-access
        self.assertEqual(cgroup._current_system_cpu, 5496872)  # pylint: disable=protected-access

    def test_get_cpu_usage_should_return_the_cpu_usage_since_its_last_invocation(self):
        osutil = get_osutil()

        cgroup = CpuCgroup("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t0"),
            os.path.join(cgroup.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "cpuacct.stat_t0")
        }

        cgroup.initialize_cpu_usage()

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t1"),
            os.path.join(cgroup.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "cpuacct.stat_t1")
        }

        cpu_usage = cgroup.get_cpu_usage()

        self.assertEqual(cpu_usage, round(100.0 * 0.000307697876885 * osutil.get_processor_cores(), 3))

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t2"),
            os.path.join(cgroup.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "cpuacct.stat_t2")
        }

        cpu_usage = cgroup.get_cpu_usage()

        self.assertEqual(cpu_usage, round(100.0 * 0.000445181085968 * osutil.get_processor_cores(), 3))

    def test_initialie_cpu_usage_should_set_the_cgroup_usage_to_0_when_the_cgroup_does_not_exist(self):
        cgroup = CpuCgroup("test", "/sys/fs/cgroup/cpu/system.slice/test")

        io_error_2 = IOError()
        io_error_2.errno = errno.ENOENT  # "No such directory"

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t0"),
            os.path.join(cgroup.path, "cpuacct.stat"): io_error_2
        }

        cgroup.initialize_cpu_usage()

        self.assertEqual(cgroup._current_cgroup_cpu, 0)  # pylint: disable=protected-access
        self.assertEqual(cgroup._current_system_cpu, 5496872)  # check the system usage just for test sanity  # pylint: disable=protected-access


    def test_initialize_cpu_usage_should_raise_an_exception_when_called_more_than_once(self):
        cgroup = CpuCgroup("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuCgroup.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "proc_stat_t0"),
            os.path.join(cgroup.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "cpuacct.stat_t0")
        }

        cgroup.initialize_cpu_usage()

        with self.assertRaises(CGroupsException):
            cgroup.initialize_cpu_usage()

    def test_get_cpu_usage_should_raise_an_exception_when_initialize_cpu_usage_has_not_been_invoked(self):
        cgroup = CpuCgroup("test", "/sys/fs/cgroup/cpu/system.slice/test")

        with self.assertRaises(CGroupsException):
            cpu_usage = cgroup.get_cpu_usage()  # pylint: disable=unused-variable


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

        with self.assertRaises(IOError) as e:
            test_mem_cg.get_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_cg.get_max_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)
