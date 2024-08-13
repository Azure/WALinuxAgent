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
import shutil

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, PolicyEngineConfigurator, ExtensionPolicyEngine, POLICY_SUPPORT_MATRIX
from tests.lib.tools import patch, data_dir, test_dir


class TestPolicyEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_data_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_policy_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
    test_input_path = os.path.join(data_dir, 'policy', "agent-extension-input.json")

    @classmethod
    def setUpClass(cls):
        # Currently, ga/policy/regorus contains a dummy binary. The unit tests require a real binary,
        # so we replace the dummy with a copy from the tests_e2e folder.
        regorus_source_path = os.path.abspath(os.path.join(data_dir, "policy/regorus"))
        cls.regorus_dest_path = os.path.abspath(os.path.join(test_dir, "..", "azurelinuxagent/ga/policy/regorus"))
        if not os.path.exists(cls.regorus_dest_path):
            shutil.copy(regorus_source_path, cls.regorus_dest_path)
        # Patch the path to regorus for all unit tests.
        cls.patcher = patch('azurelinuxagent.ga.policy.regorus.get_regorus_path', return_value=cls.regorus_dest_path)
        cls.patcher.start()
        AgentTestCase.setUpClass()


    @classmethod
    def tearDownClass(cls):
        PolicyEngineConfigurator._instance = None
        # Clean up the Regorus binary that was copied to ga/policy/regorus.
        if os.path.exists(cls.regorus_dest_path):
            os.remove(cls.regorus_dest_path)
        cls.patcher.stop()
        AgentTestCase.tearDownClass()

    def tearDown(self):
        PolicyEngineConfigurator._instance = None
        PolicyEngineConfigurator._initialized = False
        PolicyEngineConfigurator._policy_enabled = False
        AgentTestCase.tearDown(self)

    def test_configurator_get_instance_should_return_same_instance(self):
        """PolicyEngineConfigurator should be a singleton."""
        configurator_1 = PolicyEngineConfigurator.get_instance()
        configurator_2 = PolicyEngineConfigurator.get_instance()
        self.assertTrue(configurator_1 is configurator_2,
                        "PolicyEngineConfigurator.get_instance() should return the same instance.")

    def test_policy_should_be_enabled_on_supported_distro(self):
        """Policy should be enabled on all supported distros."""
        for distro_name, version in POLICY_SUPPORT_MATRIX.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.get_distro',
                       return_value=[distro_name, str(version)]):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                           return_value=True):
                    policy_enabled = PolicyEngineConfigurator.get_instance().get_policy_enabled()
                    self.assertTrue(policy_enabled, "Policy should be enabled on supported distro Ubuntu 16.04.")

    def test_policy_should_not_be_enabled_on_unsupported_distro(self):
        """Policy should NOT be enabled on unsupported like RHEL."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                policy_enabled = PolicyEngineConfigurator.get_instance().get_policy_enabled()
                self.assertFalse(policy_enabled, "Policy should not be enabled on unsupported distro RHEL 9.0.")

    def test_regorus_engine_should_be_initialized_on_supported_distro(self):
        """Regorus engine should initialize without any errors on a supported distro."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                self.assertTrue(engine.policy_engine_enabled,
                                "Regorus engine should be initialized on supported distro Ubuntu 16.04.")

    def test_regorus_engine_should_not_be_initialized_on_unsupported_distro(self):
        """Regorus policy engine should NOT be initialized on unsupported distro like RHEL."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                self.assertFalse(engine.policy_engine_enabled,
                                 "Regorus engine should not be initialized on unsupported distro RHEL 9.0.")

    def test_extension_policy_engine_should_load_successfully(self):
        """Extension policy engine should be able to load policy and data files without any errors."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = ExtensionPolicyEngine()
                self.assertTrue(engine.extension_policy_engine_enabled, "Extension policy engine should load successfully.")

    def test_policy_engine_should_add_policy(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                policy_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
                engine.add_policy(policy_path)

    def test_policy_engine_should_evaluate_query(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                engine.add_data(self.default_data_path)
                engine.add_policy(self.default_policy_path)
                engine.set_input(self.test_input_path)
                query = "data.agent_extension_policy.extensions_to_download"
                result = engine.evaluate_query(query)
                test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                self.assertTrue(result[test_ext_name]['downloadAllowed'])

    def test_should_return_allowed_list(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = ExtensionPolicyEngine()
                engine.add_data(self.default_data_path)
                engine.add_policy(self.default_policy_path)
                engine.set_input(self.test_input_path)
                query = "data.agent_extension_policy.extensions_to_download"
                result = engine.get_allowed_list()
                test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                self.assertTrue(len(result) > 0)
                self.assertTrue(test_ext_name in result)

    def test_extension_should_be_allowed(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = ExtensionPolicyEngine()
                engine.add_data(self.default_data_path)
                engine.add_policy(self.default_policy_path)
                engine.set_input(self.test_input_path)
                query = "data.agent_extension_policy.extensions_to_download"
                test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                result = engine.is_extension_download_allowed(test_ext_name)
                self.assertTrue(result)

    def test_extension_should_be_disallowed(self):
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = ExtensionPolicyEngine()
                engine.add_data(self.default_data_path)
                engine.add_policy(self.default_policy_path)
                engine.set_input(self.test_input_path)
                query = "data.agent_extension_policy.extensions_to_download"
                test_ext_name = "Random.Disallowed.Extension"
                result = engine.is_extension_download_allowed(test_ext_name)
                self.assertFalse(result)