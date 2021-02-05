# Copyright 2019 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#
import unittest

from azurelinuxagent.common.osutil.openbsd import OpenBSDOSUtil
from tests.tools import AgentTestCase
from .test_default import osutil_get_dhcp_pid_should_return_a_list_of_pids


class TestAlpineOSUtil(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        osutil_get_dhcp_pid_should_return_a_list_of_pids(self, OpenBSDOSUtil())


if __name__ == '__main__':
    unittest.main()
