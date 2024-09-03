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

import json
import os
import shutil

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, POLICY_SUPPORTED_DISTROS_MIN_VERSIONS, PolicyError
from tests.lib.tools import patch, data_dir, test_dir


class TestPolicyEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_policy_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_rule_path = os.path.join(data_dir, 'policy', "agent_policy.rego")
    input_json = {
        "extensions": {
            "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux": {
                "signingInfo": {
                    "extensionSigned": False
                }
            },
            "test2": {
                "signingInfo": {
                    "extensionSigned": True
                }
            },
            "test3": {}
        }
    }

    @classmethod
    def setUpClass(cls):

        # On a production VM, Regorus will be located in the agent package. Unit tests
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
        # Clean up the Regorus binary that was copied to ga/policy/regorus.
        if os.path.exists(cls.regorus_dest_path):
            os.remove(cls.regorus_dest_path)
        cls.patcher.stop()
        AgentTestCase.tearDownClass()

    def test_policy_should_be_enabled_on_supported_distro(self):
        """Policy should be enabled on all supported distros."""
        for distro_name, version in POLICY_SUPPORTED_DISTROS_MIN_VERSIONS.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new=distro_name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new=version):
                    with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                        engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
                        self.assertTrue(engine.is_policy_enforcement_enabled(), "Policy should be enabled on supported distro {0} {1}".format(distro_name, version))

    def test_should_raise_exception_on_unsupported_distro(self):
        """Policy should NOT be enabled on unsupported distros."""
        test_matrix = {
            "rhel": "9.0",
            "mariner": "1"
        }
        for distro_name, version in test_matrix.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new=distro_name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new=version):
                    with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                        with self.assertRaises(Exception,
                                           msg="Policy should not be enabled on unsupported distro {0} {1}".format(distro_name, version)):
                            PolicyEngine(self.default_rule_path, self.default_policy_path)

    def test_should_raise_exception_on_unsupported_architecture(self):
        """Policy should NOT be enabled on ARM64."""
        # TODO: remove this test when support for ARM64 is added.
        with patch('azurelinuxagent.ga.policy.policy_engine.get_osutil') as mock_get_osutil:
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                with self.assertRaises(PolicyError, msg="Policy should not be enabled on unsupported architecture ARM64, should have raised exception."):
                    mock_get_osutil.get_vm_arch.return_value = "arm64"
                    PolicyEngine(self.default_rule_path, self.default_policy_path)

    def test_policy_engine_should_evaluate_query(self):
        """
        Should be able to initialize policy engine and evaluate query without an error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
                    query = "data.agent_extension_policy.extensions_to_download"
                    result = engine.evaluate_query(self.input_json, query)
                    test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                    self.assertIsNotNone(result.get(test_ext_name), msg="Query should not have returned empty dict.")
                    self.assertTrue(result.get(test_ext_name).get('downloadAllowed'),
                                    msg="Query should have returned that extension is allowed.")

    def test_eval_query_should_throw_error_when_disabled(self):
        """
        When policy enforcement is disabled, evaluate_query should throw an error.
        """
        engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
        with self.assertRaises(PolicyError, msg="Should throw error when policy enforcement is disabled."):
            engine.evaluate_query(self.input_json, "data")

    def test_should_throw_error_with_invalid_rule_file(self):
        """
        Evaluate query with invalid rule file, should throw error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    with self.assertRaises(PolicyError, msg="Should throw error when input is incorrectly formatted."):
                        # pass policy file instead of rule file in init
                        invalid_rule = os.path.join(data_dir, 'policy', "agent_policy_invalid.rego")
                        engine = PolicyEngine(invalid_rule, self.default_policy_path)
                        engine.evaluate_query(self.input_json, "data")

    def test_should_throw_error_with_invalid_policy_file(self):
        """
        Evaluate query with invalid policy file, should throw error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    with self.assertRaises(PolicyError, msg="Should throw error when policy file is incorrectly formatted."):
                        invalid_policy = os.path.join(data_dir, 'policy', "agent-extension-data-invalid.json")
                        engine = PolicyEngine(self.default_rule_path, invalid_policy)
                        engine.evaluate_query(self.input_json, "data")

# TODO: add tests for all combinations of extensions and policy parameters when ExtensionPolicyEngine() class is added