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
import shutil

from azurelinuxagent.ga.cgroupcontroller import CounterNotFound
from azurelinuxagent.ga.memorycontroller import MemoryControllerV1, MemoryControllerV2
from tests.lib.tools import AgentTestCase, data_dir


class TestMemoryControllerV1(AgentTestCase):
    def test_get_metrics_v1(self):
        test_mem_controller = MemoryControllerV1("test_extension", os.path.join(data_dir, "cgroups", "v1"))

        rss_memory_usage, cache_memory_usage = test_mem_controller.get_memory_usage()
        self.assertEqual(100000, rss_memory_usage)
        self.assertEqual(50000, cache_memory_usage)

        max_memory_usage = test_mem_controller.get_max_memory_usage()
        self.assertEqual(1000000, max_memory_usage)

        swap_memory_usage = test_mem_controller.try_swap_memory_usage()
        self.assertEqual(20000, swap_memory_usage)

    def test_get_metrics_v1_when_files_not_present(self):
        test_mem_controller = MemoryControllerV1("test_extension", os.path.join(data_dir, "cgroups"))

        with self.assertRaises(IOError) as e:
            test_mem_controller.get_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_controller.get_max_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_controller.try_swap_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

    def test_get_memory_usage_v1_counters_not_found(self):
        test_file = os.path.join(self.tmp_dir, "memory.stat")
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v1", "memory.stat_missing"), test_file)
        test_mem_controller = MemoryControllerV1("test_extension", self.tmp_dir)

        with self.assertRaises(CounterNotFound):
            test_mem_controller.get_memory_usage()

        swap_memory_usage = test_mem_controller.try_swap_memory_usage()
        self.assertEqual(0, swap_memory_usage)


class TestMemoryControllerV2(AgentTestCase):
    def test_get_metrics_v2(self):
        test_mem_controller = MemoryControllerV2("test_extension", os.path.join(data_dir, "cgroups", "v2"))

        anon_memory_usage, cache_memory_usage = test_mem_controller.get_memory_usage()
        self.assertEqual(17589300, anon_memory_usage)
        self.assertEqual(134553600, cache_memory_usage)

        max_memory_usage = test_mem_controller.get_max_memory_usage()
        self.assertEqual(194494464, max_memory_usage)

        swap_memory_usage = test_mem_controller.try_swap_memory_usage()
        self.assertEqual(20000, swap_memory_usage)

        memory_throttled_events = test_mem_controller.get_memory_throttled_events()
        self.assertEqual(9, memory_throttled_events)

        memory_pressure_events = test_mem_controller.get_memory_pressure_events()
        self.assertEqual(15.00, memory_pressure_events)

    def test_get_metrics_v2_when_files_not_present(self):
        test_mem_controller = MemoryControllerV2("test_extension", os.path.join(data_dir, "cgroups"))

        with self.assertRaises(IOError) as e:
            test_mem_controller.get_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_controller.get_max_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_controller.try_swap_memory_usage()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        with self.assertRaises(IOError) as e:
            test_mem_controller.get_memory_throttled_events()

        self.assertEqual(e.exception.errno, errno.ENOENT)

        # Not raising IOError for memory pressure events as the file is optional in cgroup v2
        test_mem_controller.get_memory_pressure_events()

    def test_get_memory_usage_v2_counters_not_found(self):
        test_stat_file = os.path.join(self.tmp_dir, "memory.stat")
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v2", "memory.stat_missing"), test_stat_file)
        test_events_file = os.path.join(self.tmp_dir, "memory.events")
        shutil.copyfile(os.path.join(data_dir, "cgroups", "v2", "memory.stat_missing"), test_events_file)
        test_mem_controller = MemoryControllerV2("test_extension", self.tmp_dir)

        with self.assertRaises(CounterNotFound):
            test_mem_controller.get_memory_usage()

        with self.assertRaises(CounterNotFound):
            test_mem_controller.get_memory_throttled_events()
