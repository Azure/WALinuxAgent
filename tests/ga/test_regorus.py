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
from azurelinuxagent.ga.policy.regorus import Engine
from tests.lib.tools import patch, data_dir, test_dir, MagicMock


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
        engine.add_policy(self.default_policy_path)
        engine.add_data(self.default_data_path)
        engine.set_input(self.test_input_path)
        result = engine.eval_query("data.agent_extension_policy.extensions_to_download")
        test_ext_name = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
        self.assertTrue(result['result'][0]['expressions'][0]['value'][test_ext_name]['downloadAllowed'])

    def test_invalid_policy_should_raise_exception(self):
        """Exception should be raised when we try to add a JSON file as a policy file (should be Rego)."""
        engine = Engine()
        with self.assertRaises(Exception, msg="Adding an invalid policy file should have raised an exception."):
            engine.add_policy(self.default_data_path)

    def test_invalid_data_should_raise_exception(self):
        """Exception should be raised when we try to add a Rego file as a data file (should be JSON)."""
        engine = Engine()
        with self.assertRaises(Exception, msg="Adding an invalid data file should have raised an exception."):
            engine.add_data(self.default_policy_path)

    def test_invalid_input_should_raise_exception(self):
        """Exception should be raised when we try to add a Rego file as input (should be JSON)."""
        engine = Engine()
        with self.assertRaises(Exception, msg="Adding an invalid input file should have raised an exception."):
            engine.set_input(self.default_policy_path)

    @patch('subprocess.Popen')
    def test_eval_query_non_zero_return_code(self, mock_popen):
        """Test that {} is returned when subprocess.Popen fails."""
        # mock the behavior of subprocess.Popen to return non-zero exit code
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.communicate.return_value = (b'', b'Error occurred')  # Simulate stdout and stderr
        mock_popen.return_value = mock_process

        # test eval_query, which will use subprocess.Popen
        engine = Engine()
        with self.assertRaises(Exception, msg="Subprocess failure should have raised an exception."):
            engine.eval_query("test_query")
