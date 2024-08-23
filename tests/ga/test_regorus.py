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
from azurelinuxagent.ga.policy.regorus import Engine
from tests.lib.tools import patch, data_dir, test_dir


class TestRegorusEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_policy_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_rule_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
    input_json = None  # Input is stored in a file, and extracted into this variable during class setup.

    @classmethod
    def setUpClass(cls):
        # On a production VM, Regorus will be located in /var/lib/waagent/WALinuxAgent-x.x.x.x/bin. Unit tests
        # run within the agent directory, so we copy the executable to ga/policy/regorus and patch path.
        # Note: Regorus has not been published officially, so for now, unofficial exe is stored in tests/data/policy.s
        regorus_source_path = os.path.abspath(os.path.join(data_dir, "policy/regorus"))
        cls.regorus_dest_path = os.path.abspath(os.path.join(test_dir, "..", "azurelinuxagent/ga/policy/regorus"))
        if not os.path.exists(cls.regorus_dest_path):
            shutil.copy(regorus_source_path, cls.regorus_dest_path)
        # Patch the path to regorus for all unit tests.
        cls.patcher = patch('azurelinuxagent.ga.policy.regorus.get_regorus_path', return_value=cls.regorus_dest_path)
        cls.patcher.start()

        # We store input in a centralized file, we want to extract the JSON contents into a dict for testing.
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

    def test_should_evaluate_query_with_valid_params(self):
        """
        Eval_query should return the expected output with a valid policy, data, and input file.
        This unit test also tests the valid case for add_policy, add_data, and set_input.
        """
        engine = Engine()
        engine.add_policy(self.default_rule_path)
        engine.add_data(self.default_policy_path)
        engine.set_input(self.input_json)
        output = engine.eval_query("data.agent_extension_policy.extensions_to_download")
        result = output['result'][0]['expressions'][0]['value']
        test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
        ext_info = result.get(test_ext_name)
        self.assertIsNotNone(ext_info, msg="Query failed, should have returned result for extension.")
        self.assertTrue(ext_info.get('downloadAllowed'))

    def test_missing_rule_file_should_raise_exception(self):
        """Exception should be raised when we try to add an invalid file path as rule file."""
        engine = Engine()
        with self.assertRaises(IOError, msg="Adding a bad path to rule file should have raised an exception."):
            fake_path = "/fake/file/path"
            engine.add_policy(fake_path)

    def test_invalid_rule_file_should_raise_exception(self):
        """Exception should be raised when we try to add a rule file with invalid contents (JSON instead of Rego)."""
        engine = Engine()
        with self.assertRaises(TypeError, msg="Adding a rule file with invalid contents should have raised an exception."):
            engine.add_policy(self.default_policy_path)

    def test_missing_policy_file_should_raise_exception(self):
        """Exception should be raised when we try to add invalid file path."""
        engine = Engine()
        fake_path = "/fake/file/path"
        with self.assertRaises(IOError, msg="Adding a bad path to policy file should have raised an exception."):
            engine.add_data(fake_path)

    def test_invalid_policy_file_should_raise_exception(self):
        """Exception should be raised when we try to add a Rego file as a data file (should be JSON)."""
        engine = Engine()
        with self.assertRaises(TypeError, msg="Adding an invalid data file should have raised an exception."):
            engine.add_data(self.default_rule_path)

    def test_invalid_input_should_raise_exception(self):
        """Exception should be raised when we try to add a Rego file as input (should be JSON)."""
        engine = Engine()
        with self.assertRaises(Exception, msg="Adding an invalid input file should have raised an exception."):
            engine.set_input(self.default_rule_path)

    def test_should_set_input_with_str(self):
        """Set input should accept a string type, this shouldn't throw an error."""
        engine = Engine()
        input_str = json.dumps(self.input_json)
        engine.set_input(input_str)

    def test_eval_query_should_raise_invalid_file(self):
        """Test that error is raised when regorus eval CLI fails."""
        engine = Engine()
        with self.assertRaises(Exception, msg="Subprocess failure should have raised an exception."):
            invalid_rule_file = os.path.join(data_dir, 'policy', "agent_extension_policy_invalid.rego")
            engine.add_policy(invalid_rule_file)
            engine.eval_query("test_query")


