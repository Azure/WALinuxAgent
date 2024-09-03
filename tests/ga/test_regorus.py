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
import tempfile


from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.regorus import Regorus, PolicyError
from tests.lib.tools import patch, data_dir, test_dir

ALLOWED_EXT = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
RANDOM_EXT = "Random.Ext.Name"


class TestRegorusEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_policy_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_rule_path = os.path.join(data_dir, 'policy', "agent_policy.rego")
    default_input = {
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
        # Note: Regorus has not been published officially, so for now, unofficial exe is stored in tests/data/policy.s
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

    def test_download_allowed_should_be_true_if_extension_in_allowlist(self):
        """
        If extension is in the allowlist, downloadAllowed=True. Global allowlist rule shouldn't matter.
        """
        allowlist_only_cases = [True, False]
        for allowlist_only in allowlist_only_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": False
                    },
                    "allowListOnly": allowlist_only
                },
                "azureGuestExtensionsPolicy": {
                    ALLOWED_EXT: {}
                }
            }

            input_dict = {
                "extensions": {
                    ALLOWED_EXT: {}  # Extension in allowlist
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = Regorus(policy_file.name, self.default_rule_path)
                output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
                result = output['result'][0]['expressions'][0]['value']
                download_allowed = result.get(ALLOWED_EXT).get("downloadAllowed")
                self.assertTrue(download_allowed, msg="Extension is in allowlist, so downloadAllowed should be True.")

    def test_download_allowed_should_depend_on_global_allowlist_rule_if_extension_not_in_allowlist(self):
        """
        If extension is not in the allowlist:
         - downloadAllowed = true if global allowlist rule not enabled (allowlistOnly = false)
         - downloadAllowed = false if global allowlist rule enabled (allowlistOnly = true)
        """
        allowlist_only_cases = [True, False]
        for allowlist_only in allowlist_only_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": False
                    },
                    "allowListOnly": allowlist_only
                },
                "azureGuestExtensionsPolicy": {
                    ALLOWED_EXT: {}
                }
            }

            input_dict = {
                "extensions": {
                    RANDOM_EXT: {}      # Not included in the allowlist.
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = Regorus(policy_file.name, self.default_rule_path)
                output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
                result = output['result'][0]['expressions'][0]['value']
                download_allowed = result.get(RANDOM_EXT).get("downloadAllowed")
                self.assertEqual(download_allowed, (not allowlist_only),
                                msg="Extension is not in allowlist, allowListOnly is {0} so downloadAllowed should be {1}"
                                 .format(download_allowed, allowlist_only))

    def test_signing_validated_should_depend_on_signature_if_individual_signing_rule_true(self):
        """
        If individual signing rule is enforced, signingValidated=true only if extension is signed.
        Global signing rule shouldn't matter.
        """
        # Should be same result for global signing rule true/false, so we test both cases.
        global_signing_rule_cases = [True, False]
        for global_signing_rule in global_signing_rule_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": global_signing_rule
                    },
                    "allowListOnly": False
                },
                "azureGuestExtensionsPolicy": {
                    ALLOWED_EXT: {
                        "signingRules": {
                            "extensionSigned": True  # ALLOWED_EXT must be signed
                        }
                    }
                }
            }

            # Extension should be validated only if it signed. Test both when extension is signed and not.
            is_ext_signed_values = (True, False)
            for is_ext_signed in is_ext_signed_values:
                input_dict = {
                    "extensions": {
                        ALLOWED_EXT: {
                            "signingInfo": {
                                "extensionSigned": is_ext_signed
                            }
                        }
                    }
                }

                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                    json.dump(policy, policy_file, indent=4)
                    policy_file.flush()
                    engine = Regorus(policy_file.name, self.default_rule_path)
                    output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
                    result = output['result'][0]['expressions'][0]['value']
                    signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
                    self.assertEqual(signing_validated, is_ext_signed, msg="Extension should only be validated if signed.")

    def test_signing_validated_should_be_true_if_individual_signing_rule_false(self):
        """
        If individual signing rule is false (not enforced), signingValidated=true. Global signing rule shouldn't matter.
        """
        # Should be same result for global signing rule true/false, so we test both cases.
        global_signing_rule_cases = [True, False]
        for global_signing_rule in global_signing_rule_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": global_signing_rule
                    },
                    "allowListOnly": False
                },
                "azureGuestExtensionsPolicy": {
                    ALLOWED_EXT: {
                        "signingRules": {
                            "extensionSigned": False
                        }
                    }
                }
            }

            is_ext_signed_values = (True, False)
            for is_ext_signed in is_ext_signed_values:
                input_dict = {
                    "extensions": {
                        ALLOWED_EXT: {
                            "signingInfo": {
                                "extensionSigned": is_ext_signed
                            }
                        }
                    }
                }

                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                    json.dump(policy, policy_file, indent=4)
                    policy_file.flush()
                    engine = Regorus(policy_file.name, self.default_rule_path)
                    output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
                    result = output['result'][0]['expressions'][0]['value']
                    signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
                    self.assertTrue(signing_validated, msg="Individual signing rule is false, so signingValidated should be true.")

    def test_signing_validated_should_depend_on_signature_if_global_signing_rule_true_and_no_individual_rule(self):
        """
        If individual signing rule doesn't exist, signingValidated depends on global signing rule.
        If global signing rule is enforced, signingValidated = true only if extension is signed.
        """
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": True
                },
                "allowListOnly": False
            }
        }

        # Extension should be validated only if it signed. Test both when extension is signed and not.
        is_ext_signed_values = (True, False)
        for is_ext_signed in is_ext_signed_values:
            input_dict = {
                "extensions": {
                    ALLOWED_EXT: {
                        "signingInfo": {
                            "extensionSigned": is_ext_signed
                        }
                    }
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = Regorus(policy_file.name, self.default_rule_path)
                output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
                result = output['result'][0]['expressions'][0]['value']
                signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
                self.assertEqual(signing_validated, is_ext_signed, msg="Extension should only be validated if signed.")

    def test_signing_validated_should_be_true_if_global_signing_rule_false_and_no_individual_rule(self):
        """
        If individual signing rule doesn't exist, signingValidated depends on global signing rule.
        If global signing rule not enforced, signingValidated = true.
        """
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": False
                },
                "allowListOnly": False
            }
        }

        # Extension should be validated always. Test both when extension is signed and not.
        is_ext_signed_values = (True, False)
        for is_ext_signed in is_ext_signed_values:
            input_dict = {
                "extensions": {
                    ALLOWED_EXT: {
                        "signingInfo": {
                            "extensionSigned": is_ext_signed
                        }
                    }
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = Regorus(policy_file.name, self.default_rule_path)
                output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
                result = output['result'][0]['expressions'][0]['value']
                signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
                self.assertTrue(signing_validated, msg="Global signing rule is false so extension should always be validated.")

    def test_download_allowed_should_be_false_if_policy_invalid(self):
        """
        If policy file is missing a section, downloadAllowed should be invalid. No exception should be raised.
        """
        policy = {
            "invalid_section": {
                "signingRules": {
                    "extensionSigned": False
                },
                "allowListOnly": False
            }
        }

        input_dict = {
            "extensions": {
                ALLOWED_EXT: {
                    "signingInfo": {
                        "extensionSigned": True
                    }
                }
            }
        }

        # Policy file is invalid, missing azureGuestAgentPolicy section. No extensions should be allowed.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = Regorus(policy_file.name, self.default_rule_path)
            output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
            result = output['result'][0]['expressions'][0]['value']
            allowed_ext_allowed = result.get(ALLOWED_EXT).get("downloadAllowed")
            self.assertFalse(allowed_ext_allowed, msg="Policy file is invalid so all extensions should be disallowed.")

    def test_eval_query_should_raise_exception_for_bad_rule_file_path(self):
        """Exception should be raised when we eval_query with invalid rule file path."""
        engine = Regorus("/fake/policy/file/path", self.default_rule_path)
        with self.assertRaises(PolicyError, msg="Evaluating query should raise exception when rule file doesn't exist."):
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_invalid_rule_file_syntax(self):
        """Exception should be raised when we eval_query with invalid rule file syntax."""
        invalid_rule = os.path.join(data_dir, 'policy', "agent_policy_invalid.rego")
        with self.assertRaises(PolicyError, msg="Evaluating query should raise exception when rule file syntax is invalid"):
            engine = Regorus(self.default_policy_path, invalid_rule)
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_bad_policy_file_path(self):
        """Exception should be raised when we eval_query with invalid policy file path."""
        invalid_policy = os.path.join("agent-extension-data-invalid.json")
        with self.assertRaises(PolicyError, msg="Evaluating query should raise exception when policy file doesn't exist."):
            engine = Regorus(invalid_policy, self.default_rule_path)
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_invalid_policy_file_syntax(self):
        """Exception should be raised when we eval_query with bad data file contents."""
        invalid_policy = os.path.join(data_dir, 'policy', "agent-extension-data-invalid.json")
        with self.assertRaises(PolicyError, msg="Evaluating query should raise exception when policy file syntax is invalid."):
            engine = Regorus(invalid_policy, self.default_rule_path)
            engine.eval_query(self.default_input, "data")
