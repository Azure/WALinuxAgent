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

from azurelinuxagent.common.cgroups import CGroupsTelemetry, CGroups
from tests.tools import *


class TestCGroups(AgentTestCase):
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