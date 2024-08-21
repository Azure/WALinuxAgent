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
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, POLICY_SUPPORTED_DISTROS_MIN_VERSIONS
from tests.lib.tools import patch, data_dir, test_dir, MagicMock


class TestPolicyEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_data_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_policy_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
    input_json = None  # Input is stored in a file, and extracted into this variable during class setup.

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

        # We store input in a centralized file, we want to extract the JSON contents into a dict for testing.
        # TODO: remove this logic once we add tests for ExtensionPolicyEngine
        with open(os.path.join(data_dir, 'policy', "agent-extension-input.json"), 'r') as input_file:
            cls.input_json = json.load(input_file)
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
            with patch('azurelinuxagent.ga.policy.policy_engine.get_distro',
                       return_value=[distro_name, str(version)]):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                           return_value=True):
                    engine = PolicyEngine(self.default_policy_path, self.default_data_path)
                    self.assertTrue(engine.policy_engine_enabled, "Policy should be enabled on supported distro Ubuntu 16.04.")

    def test_should_raise_exception_on_unsupported_distro(self):
        """Policy should NOT be enabled on unsupported like RHEL."""
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                with self.assertRaises(Exception, msg="Policy should not be enabled on unsupported distro RHEL 9.0, should have raised exception."):
                    PolicyEngine(self.default_policy_path, self.default_data_path)

    def test_should_raise_exception_on_unsupported_architecture(self):
        """Policy should NOT be enabled on ARM64."""
        # TODO: remove this test when support for ARM64 is added.
        with patch('azurelinuxagent.ga.policy.policy_engine.get_osutil') as mock_get_osutil:
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                with self.assertRaises(Exception, msg="Policy should not be enabled on unsupported architecture ARM64, should have raised exception."):
                    mock_osutil = MagicMock()
                    mock_osutil.get_vm_arch.return_value = "arm64"
                    mock_get_osutil.return_value = mock_osutil
                    PolicyEngine(self.default_policy_path, self.default_data_path)

    def test_policy_engine_should_evaluate_query(self):
        """
        Should be able to add policy, data, input, and evaluate query without an error.
        This tests the happy path for add_policy, add_data, and set_input as well.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['ubuntu', '16.04']):
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine(self.default_policy_path, self.default_data_path)
                query = "data.agent_extension_policy.extensions_to_download"
                result = engine.evaluate_query(self.input_json, query)
                test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                self.assertIsNotNone(result.get(test_ext_name), msg="Query should not have returned empty dict.")
                self.assertTrue(result.get(test_ext_name).get('downloadAllowed'),
                                msg="Query should have returned that extension is allowed.")

    def test_eval_query_should_be_no_op(self):
        """
        When policy enforcement is disabled, evaluate_query should throw an error.
        """
        engine = PolicyEngine(self.default_policy_path, self.default_data_path)
        query = "data.agent_extension_policy.extensions_to_download"
        with self.assertRaises(Exception, msg="Adding an invalid policy file should have raised an exception."):
            engine.evaluate_query(self.input_json, query)

