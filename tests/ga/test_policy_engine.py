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

import os

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, PolicyEngineConfigurator, ExtensionPolicyEngine
from tests.lib.tools import patch
import shutil


class TestPolicyEngine(AgentTestCase):
    dummy_bin = None

    # @classmethod
    # def setUpClass(cls):
    #     # replace dummy regorus binary in ga folder with real binary from tests_e2e folder
    #     current_dir = os.path.dirname(os.path.abspath(__file__))
    #     real_bin = os.path.abspath(
    #         os.path.join(current_dir, "..", "..", "tests_e2e/tests/executables/regorus.cpython-38-x86_64-linux-gnu.so"))
    #     dummy_bin_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "azurelinuxagent/ga/policy/regorus/"))
    #     cls.dummy_bin = os.path.abspath(os.path.join(dummy_bin_dir, "regorus.cpython-38-x86_64-linux-gnu.so"))
    #     os.makedirs(os.path.dirname(dummy_bin_dir), exist_ok=True)
    #     if not os.path.exists(cls.dummy_bin):
    #         shutil.copy(real_bin, cls.dummy_bin)
    #     AgentTestCase.setUpClass()


    @classmethod
    def tearDownClass(cls):
        PolicyEngineConfigurator._instance = None
        # if os.path.exists(cls.dummy_bin):
        #     os.remove(cls.dummy_bin)
        AgentTestCase.tearDownClass()

    def tearDown(self):
        PolicyEngineConfigurator._instance = None
        PolicyEngineConfigurator._initialized = False
        PolicyEngineConfigurator._policy_enabled = False
        patch.stopall()
        AgentTestCase.tearDown(self)

    def test_configurator_get_instance_should_return_same_instance(self):
        """PolicyEngineConfigurator should be a singleton."""
        configurator_1 = PolicyEngineConfigurator.get_instance()
        configurator_2 = PolicyEngineConfigurator.get_instance()
        self.assertIs(configurator_1, configurator_2,
                      "PolicyEngineConfigurator.get_instance() should return the same instance.")

    def test_policy_should_be_enabled_on_supported_distro(self):
        """Policy should be enabled on supported distro like Ubuntu 16.04."""
        with patch('azurelinuxagent.common.version.get_distro', return_value=['ubuntu', '16.04']), \
                patch('azurelinuxagent.common.conf.get_extension_policy_enabled', return_value=True):
            policy_enabled = PolicyEngineConfigurator.get_instance().get_policy_enabled()
            self.assertTrue(policy_enabled, "Policy should be enabled on supported distro Ubuntu 16.04.")

    def test_policy_should_not_be_enabled_on_unsupported_distro(self):
        """Policy should NOT be enabled on unsupported like RHEL."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']), \
                patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            policy_enabled = PolicyEngineConfigurator.get_instance().get_policy_enabled()
            self.assertFalse(policy_enabled, "Policy should not be enabled on unsupported distro RHEL 9.0.")

    def test_regorus_engine_should_be_initialized_on_supported_distro(self):
        """Regorus engine should initialize without any errors on a supported distro."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']), \
                patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            engine = PolicyEngine()
            self.assertTrue(engine.policy_engine_enabled,
                            "Regorus engine should be initialized on supported distro Ubuntu 16.04.")

    def test_regorus_engine_should_not_be_initialized_on_unsupported_distro(self):
        """Regorus policy engine should NOT be initialized on unsupported distro like RHEL."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']), \
                patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            engine = PolicyEngine()
            self.assertFalse(engine.policy_engine_enabled,
                             "Regorus engine should not be initialized on unsupported distro RHEL 9.0.")

    def test_extension_policy_engine_should_load_successfully(self):
        """Extension policy engine should be able to load policy and data files without any errors."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']), \
                   patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            engine = ExtensionPolicyEngine()
            self.assertTrue(engine.extension_policy_engine_enabled, "Extension policy engine should load successfully.")


