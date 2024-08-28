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
import shutil

from azurelinuxagent.ga.cgroupcontroller import MetricsCounter
from azurelinuxagent.ga.cpucontroller import CpuControllerV1, CpuControllerV2
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from tests.lib.tools import AgentTestCase, patch, data_dir


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):  # pylint: disable=unused-variable
        waste += random.random()
    return waste


class TestCpuControllerV1(AgentTestCase):
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
        TestCpuControllerV1.mock_read_file_map.clear()

    def test_initialize_cpu_usage_v1_should_set_current_cpu_usage(self):
        controller = CpuControllerV1("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t0"),
            os.path.join(controller.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t0")
        }

        controller.initialize_cpu_usage()

        self.assertEqual(controller._current_cgroup_cpu, 63763)
        self.assertEqual(controller._current_system_cpu, 5496872)

    def test_get_cpu_usage_v1_should_return_the_cpu_usage_since_its_last_invocation(self):
        osutil = get_osutil()

        controller = CpuControllerV1("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t0"),
            os.path.join(controller.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t0")
        }

        controller.initialize_cpu_usage()

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t1"),
            os.path.join(controller.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t1")
        }

        cpu_usage = controller.get_cpu_usage()

        self.assertEqual(cpu_usage, round(100.0 * 0.000307697876885 * osutil.get_processor_cores(), 3))

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t2"),
            os.path.join(controller.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t2")
        }

        cpu_usage = controller.get_cpu_usage()

        self.assertEqual(cpu_usage, round(100.0 * 0.000445181085968 * osutil.get_processor_cores(), 3))

    def test_initialize_cpu_usage_v1_should_set_the_cgroup_usage_to_0_when_the_cgroup_does_not_exist(self):
        controller = CpuControllerV1("test", "/sys/fs/cgroup/cpu/system.slice/test")

        io_error_2 = IOError()
        io_error_2.errno = errno.ENOENT  # "No such directory"

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t0"),
            os.path.join(controller.path, "cpuacct.stat"): io_error_2
        }

        controller.initialize_cpu_usage()

        self.assertEqual(controller._current_cgroup_cpu, 0)
        self.assertEqual(controller._current_system_cpu, 5496872)  # check the system usage just for test sanity

    def test_initialize_cpu_usage_v1_should_raise_an_exception_when_called_more_than_once(self):
        controller = CpuControllerV1("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV1.mock_read_file_map = {
            "/proc/stat": os.path.join(data_dir, "cgroups", "v1", "proc_stat_t0"),
            os.path.join(controller.path, "cpuacct.stat"): os.path.join(data_dir, "cgroups", "v1", "cpuacct.stat_t0")
        }

        controller.initialize_cpu_usage()

        with self.assertRaises(CGroupsException):
            controller.initialize_cpu_usage()

    def test_get_cpu_usage_v1_should_raise_an_exception_when_initialize_cpu_usage_has_not_been_invoked(self):
        controller = CpuControllerV1("test", "/sys/fs/cgroup/cpu/system.slice/test")

        with self.assertRaises(CGroupsException):
            cpu_usage = controller.get_cpu_usage()  # pylint: disable=unused-variable

    def test_get_throttled_time_v1_should_return_the_value_since_its_last_invocation(self):
        test_file = os.path.join(self.tmp_dir, "cpu.stat")
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v1", "cpu.stat_t0"), test_file)  # throttled_time = 50
        controller = CpuControllerV1("test", self.tmp_dir)
        controller.initialize_cpu_usage()
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v1", "cpu.stat_t1"), test_file)  # throttled_time = 2075541442327

        throttled_time = controller.get_cpu_throttled_time()

        self.assertEqual(throttled_time, round(float(2075541442327 - 50) / 1E9, 3), "The value of throttled_time is incorrect")

    def test_get_tracked_metrics_v1_should_return_the_throttled_time(self):
        controller = CpuControllerV1("test", os.path.join(data_dir, "cgroups", "v1"))
        controller.initialize_cpu_usage()

        def find_throttled_time(metrics):
            return [m for m in metrics if m.counter == MetricsCounter.THROTTLED_TIME]

        found = find_throttled_time(controller.get_tracked_metrics())
        self.assertTrue(len(found) == 0, "get_tracked_metrics should not fetch the throttled time by default. Found: {0}".format(found))

        found = find_throttled_time(controller.get_tracked_metrics(track_throttled_time=True))
        self.assertTrue(len(found) == 1, "get_tracked_metrics should have fetched the throttled time by default. Found: {0}".format(found))


class TestCpuControllerV2(AgentTestCase):
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
        TestCpuControllerV2.mock_read_file_map.clear()

    def test_initialize_cpu_usage_v2_should_set_current_cpu_usage(self):
        controller = CpuControllerV2("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t0"),
            os.path.join(controller.path, "cpu.stat"): os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t0")
        }

        controller.initialize_cpu_usage()

        self.assertEqual(controller._current_cgroup_cpu, 817045397 / 1E6)
        self.assertEqual(controller._current_system_cpu, 776968.02)

    def test_get_cpu_usage_v2_should_return_the_cpu_usage_since_its_last_invocation(self):
        controller = CpuControllerV2("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t0"),
            os.path.join(controller.path, "cpu.stat"): os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t0")
        }

        controller.initialize_cpu_usage()

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t1"),
            os.path.join(controller.path, "cpu.stat"): os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t1")
        }

        cpu_usage = controller.get_cpu_usage()

        cgroup_usage_delta = (819624087 / 1E6) - (817045397 / 1E6)
        system_usage_delta = 777350.57 - 776968.02
        self.assertEqual(cpu_usage, round(100.0 * cgroup_usage_delta/system_usage_delta, 3))

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t2"),
            os.path.join(controller.path, "cpu.stat"): os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t2")
        }

        cpu_usage = controller.get_cpu_usage()

        cgroup_usage_delta = (822052295 / 1E6) - (819624087 / 1E6)
        system_usage_delta = 779218.68 - 777350.57
        self.assertEqual(cpu_usage, round(100.0 * cgroup_usage_delta/system_usage_delta, 3))

    def test_initialize_cpu_usage_v2_should_set_the_cgroup_usage_to_0_when_the_cgroup_does_not_exist(self):
        controller = CpuControllerV2("test", "/sys/fs/cgroup/cpu/system.slice/test")

        io_error_2 = IOError()
        io_error_2.errno = errno.ENOENT  # "No such directory"

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t0"),
            os.path.join(controller.path, "cpu.stat"): io_error_2
        }

        controller.initialize_cpu_usage()

        self.assertEqual(controller._current_cgroup_cpu, 0)
        self.assertEqual(controller._current_system_cpu, 776968.02)  # check the system usage just for test sanity

    def test_initialize_cpu_usage_v2_should_raise_an_exception_when_called_more_than_once(self):
        controller = CpuControllerV2("test", "/sys/fs/cgroup/cpu/system.slice/test")

        TestCpuControllerV2.mock_read_file_map = {
            "/proc/uptime": os.path.join(data_dir, "cgroups", "v2", "proc_uptime_t0"),
            os.path.join(controller.path, "cpu.stat"): os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t0")
        }

        controller.initialize_cpu_usage()

        with self.assertRaises(CGroupsException):
            controller.initialize_cpu_usage()

    def test_get_cpu_usage_v2_should_raise_an_exception_when_initialize_cpu_usage_has_not_been_invoked(self):
        controller = CpuControllerV2("test", "/sys/fs/cgroup/cpu/system.slice/test")

        with self.assertRaises(CGroupsException):
            cpu_usage = controller.get_cpu_usage()  # pylint: disable=unused-variable

    def test_get_throttled_time_v2_should_return_the_value_since_its_last_invocation(self):
        test_file = os.path.join(self.tmp_dir, "cpu.stat")
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t0"), test_file)  # throttled_time = 15735198706
        controller = CpuControllerV2("test", self.tmp_dir)
        controller.initialize_cpu_usage()
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v2", "cpu.stat_t1"), test_file)  # throttled_usec = 15796563650

        throttled_time = controller.get_cpu_throttled_time()

        self.assertEqual(throttled_time, round(float(15796563650 - 15735198706) / 1E6, 3), "The value of throttled_time is incorrect")

    def test_get_tracked_metrics_v2_should_return_the_throttled_time(self):
        controller = CpuControllerV2("test", os.path.join(data_dir, "cgroups", "v2"))
        controller.initialize_cpu_usage()

        def find_throttled_time(metrics):
            return [m for m in metrics if m.counter == MetricsCounter.THROTTLED_TIME]

        found = find_throttled_time(controller.get_tracked_metrics())
        self.assertTrue(len(found) == 0, "get_tracked_metrics should not fetch the throttled time by default. Found: {0}".format(found))

        found = find_throttled_time(controller.get_tracked_metrics(track_throttled_time=True))
        self.assertTrue(len(found) == 1, "get_tracked_metrics should have fetched the throttled time by default. Found: {0}".format(found))
