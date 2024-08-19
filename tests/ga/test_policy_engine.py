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
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, PolicyEngineConfigurator, POLICY_SUPPORTED_DISTROS
from tests.lib.tools import patch, data_dir, test_dir


class TestPolicyEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_data_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_policy_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
    test_input_path = os.path.join(data_dir, 'policy', "agent-extension-input.json")

    @classmethod
    def setUpClass(cls):
        # On a production VM, Regorus will be located in /var/lib/waagent/WALinuxAgent-x.x.x.x/bin. Unit tests
        # run within the agent directory, so we copy the executable to ga/policy/regorus and patch path.
        # Note: Regorus has not been published officially, so for now, unofficial exe is stored in tests/data/policy.
        regorus_source_path = os.path.abspath(os.path.join(data_dir, "policy/regorus"))
        cls.regorus_dest_path = os.path.abspath(os.path.join(test_dir, "..", "azurelinuxagent/ga/policy/regorus"))
        if not os.path.exists(cls.regorus_dest_path):
            shutil.copy(regorus_source_path, cls.regorus_dest_path)
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
        for distro_name, version in POLICY_SUPPORTED_DISTROS.items():
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

    def test_policy_should_not_be_enabled_on_unsupported_architecture(self):
        """Policy should NOT be enabled on ARM64."""
        # TODO: remove this test when support for ARM64 is added.
        with patch('azurelinuxagent.ga.policy.policy_engine.platform.machine', return_value='arm64'):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                policy_enabled = PolicyEngineConfigurator.get_instance().get_policy_enabled()
                self.assertFalse(policy_enabled, "Policy should not be enabled on unsupported architecture ARM64.")

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

    def test_policy_engine_should_add_policy(self):
        """Policy engine should be able to add a policy without an error."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                policy_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
                engine.add_policy(policy_path)

    def test_policy_engine_should_evaluate_query(self):
        """
        Should be able to add policy, data, input, and evaluate query without an error.
        This tests the happy path for add_policy, add_data, and set_input as well.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine()
                engine.add_data(self.default_data_path)
                engine.add_policy(self.default_policy_path)
                engine.set_input(self.test_input_path)
                query = "data.agent_extension_policy.extensions_to_download"
                result = engine.evaluate_query(query)
                test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                self.assertTrue(result[test_ext_name]['downloadAllowed'],
                                msg="Query should have returned that extension is allowed.")

    def test_eval_query_should_be_no_op(self):
        """
        When policy enforcement is disabled, eval_query should return {} and not throw an error.
        """
        engine = PolicyEngine()
        engine.add_data(self.default_data_path)
        engine.add_policy(self.default_policy_path)
        engine.set_input(self.test_input_path)
        query = "data.agent_extension_policy.extensions_to_download"
        result = engine.evaluate_query(query)
        self.assertEqual(result, {}, msg="Query should have returned an empty dict.")

