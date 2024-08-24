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

from azurelinuxagent.ga.cgroupcontroller import _CgroupController
from tests.lib.tools import AgentTestCase, patch


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):  # pylint: disable=unused-variable
        waste += random.random()
    return waste


class TestCgroupController(AgentTestCase):
    def test_is_active(self):
        test_metrics = _CgroupController("test_extension", self.tmp_dir)

        with open(os.path.join(self.tmp_dir, "cgroup.procs"), mode="wb") as tasks:
            tasks.write(str(1000).encode())

        self.assertEqual(True, test_metrics.is_active())

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_file_not_present(self, patch_periodic_warn):
        test_metrics = _CgroupController("test_extension", self.tmp_dir)
        self.assertFalse(test_metrics.is_active())

        self.assertEqual(0, patch_periodic_warn.call_count)

    @patch("azurelinuxagent.common.logger.periodic_warn")
    def test_is_active_incorrect_file(self, patch_periodic_warn):
        open(os.path.join(self.tmp_dir, "cgroup.procs"), mode="wb").close()
        test_metrics = _CgroupController("test_extension", os.path.join(self.tmp_dir, "cgroup.procs"))
        self.assertEqual(False, test_metrics.is_active())
        self.assertEqual(1, patch_periodic_warn.call_count)
