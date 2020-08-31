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

from azurelinuxagent.common.osutil.default import DefaultOSUtil, shellutil # pylint: disable=unused-import
from tests.tools import AgentTestCase, patch # pylint: disable=unused-import


class DefaultOsUtilTestCase(AgentTestCase):
    def test_default_service_name(self):
        self.assertEqual(DefaultOSUtil().get_service_name(), "waagent")
