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

from azurelinuxagent.common.cgroupapi import FileSystemCgroupsApi
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from tests.tools import *


@skip_if_predicate_false(lambda: False, "TODO: Need unit tests")
class TestCGroupConfigurator(AgentTestCase):
    #
    # TODO -- Need to write actual tests
    #
    def test_dummy(self):
        pass