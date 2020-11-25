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
# Requires Python 2.6+ and Openssl 1.0+
#
from azurelinuxagent.common.AgentGlobals import AgentGlobals, MultiConfigFeature
from tests.tools import AgentTestCase, patch


class TestAgentGlobals(AgentTestCase):

    def test_it_should_set_supported_features_correctly(self):

        multi_config_name = MultiConfigFeature().name

        with patch("azurelinuxagent.common.AgentGlobals.MultiConfigFeature.__SUPPORTED", False):
            self.assertNotIn(multi_config_name, AgentGlobals.supported_features, "MultiConfig should not be there")

        with patch("azurelinuxagent.common.AgentGlobals.MultiConfigFeature.__SUPPORTED", True):
            self.assertIn(multi_config_name, AgentGlobals.supported_features, "MultiConfig should be there")