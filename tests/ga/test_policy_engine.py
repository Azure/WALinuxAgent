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

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine
from tests.lib.tools import patch


class TestPolicyEngine(AgentTestCase):
    def test_policy_enforcement_should_be_enabled(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            engine = PolicyEngine()
            self.assertTrue(engine.is_policy_enforcement_enabled(),
                            msg="Conf flag is set to true so policy enforcement should be enabled.")

    def test_policy_enforcement_should_be_disabled(self):
        engine = PolicyEngine()
        self.assertFalse(engine.is_policy_enforcement_enabled(),
                         msg="Conf flag is set to false so policy enforcement should be disabled.")

