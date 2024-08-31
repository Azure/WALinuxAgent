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
from azurelinuxagent.ga.policy.regorus import Regorus
from tests.lib.tools import patch, data_dir, test_dir

ALLOWED_EXT = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
RANDOM_EXT = "Random.Ext.Name"


class TestRegorusEngine(AgentTestCase):
    patcher = None
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_policy_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_rule_path = os.path.join(data_dir, 'policy', "agent_policy.rego")
    default_input = """
        {
            "extensions": {
                "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux": {
                    "signingInfo": {
                        "extensionSigned": false
                    }
                },
                "test2": {
                    "signingInfo": {
                        "extensionSigned": true
                    }
                },
                "test3": {}
            }
        }
    """

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

    def test_download_allowed_should_be_true_if_allowlist_false(self):
        """If global allowlist rule is not enabled, downloadAllowed = true for all extensions."""
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": False
                },
                "allowListOnly": False
            }
        }

        input_dict = {
            "extensions": {
                ALLOWED_EXT: {},
                RANDOM_EXT: {}
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = Regorus(policy_file.name, self.default_rule_path)
            output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
            result = output['result'][0]['expressions'][0]['value']
            allowed_ext_allowed = result.get(ALLOWED_EXT).get("downloadAllowed")
            self.assertTrue(allowed_ext_allowed, msg="All extensions should be allowed to download.")
            random_ext_allowed = result.get(RANDOM_EXT).get("downloadAllowed")
            self.assertTrue(random_ext_allowed, msg="All extensions should be allowed to download.")

    def test_download_allowed_should_depend_on_allowlist_if_allowlist_true(self):
        """
        If global allowlist rule is enabled, downloadAllowed = true only if extension in allowlist.
        """
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": False
                },
                "allowListOnly": True
            },
            "azureGuestExtensionsPolicy": {
                ALLOWED_EXT: {}
            }
        }

        input_dict = {
            "extensions": {
                ALLOWED_EXT: {},    # in allowlist, should be allowed.
                RANDOM_EXT: {}      # NOT in allowlist, should not be allowed.
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = Regorus(policy_file.name, self.default_rule_path)
            output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
            result = output['result'][0]['expressions'][0]['value']
            allowed_download_allowed = result.get(ALLOWED_EXT).get("downloadAllowed")
            self.assertTrue(allowed_download_allowed, msg="Extension download should be allowed if present in allowlist.")
            random_download_allowed = result.get(RANDOM_EXT).get("downloadAllowed")
            self.assertFalse(random_download_allowed, msg="Extension download should not be allowed if not present in allowlist.")

    def test_should_enforce_individual_signing_rule(self):
        """
        If individual signing rule is enabled, signingValidated = true ONLY if extension is signed.
        """
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": False
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

        # Extension should be validated only if it signed. Test both cases.
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
                self.assertEqual(signing_validated, is_ext_signed, msg="Extension should be validated if signed.")

    def test_should_enforce_global_signing_rule(self):
        """
        If global signing rule is enabled and no individual signing rule is present, signingValidated = true ONLY if
        extension is signed.
        """
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": True
                },
                "allowListOnly": False
            }
        }

        # Extension should be validated only if it signed. Test both cases.
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
                self.assertEqual(signing_validated, is_ext_signed, msg="Extension should be validated if signed.")

    def test_should_not_enforce_global_signing_rule_if_individual_rule_disabled(self):
        """
        If present, individual signing rule takes precedence over global signing rule.
        If global signing rule enabled but an individual extension has signing rule disabled,
        then signingValidated = true for that extension.
        Any extension without an individual signing rule must be signed to be validated.
        """

        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": True
                },
                "allowListOnly": False
            },
            "azureGuestExtensionsPolicy": {
                ALLOWED_EXT: {
                    "signingRules": {
                        "extensionSigned": False  # ALLOWED_EXT does not need to be signed
                    }
                }
            }
        }

        input_dict = {
            "extensions": {
                ALLOWED_EXT: {
                    "signingInfo": {
                        "extensionSigned": False
                    }
                },
                RANDOM_EXT: {
                    "signingInfo": {
                        "extensionSigned": False
                    }
                }
            }
        }

        # ALLOWED_EXT should be validated, RANDOM_EXT should not.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = Regorus(policy_file.name, self.default_rule_path)
            output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
            result = output['result'][0]['expressions'][0]['value']
            allowed_signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
            self.assertTrue(allowed_signing_validated, msg="Individual signing rule disabled so extension should be validated.")
            random_signing_validated = result.get(RANDOM_EXT).get("signingValidated")
            self.assertFalse(random_signing_validated, msg="Global signing rule enabled so extension should not be validated")

    def test_no_signing_rule_should_validate_all(self):
        policy = {
            "azureGuestAgentPolicy": {
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
                },
                RANDOM_EXT: {
                    "signingInfo": {
                        "extensionSigned": False
                    }
                }
            }
        }

        # All extensions should be validated, regardless of signing status.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = Regorus(policy_file.name, self.default_rule_path)
            output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_validated")
            result = output['result'][0]['expressions'][0]['value']
            allowed_signing_validated = result.get(ALLOWED_EXT).get("signingValidated")
            self.assertTrue(allowed_signing_validated, msg="No signing rules enforced so extension should be validated.")
            random_signing_validated = result.get(RANDOM_EXT).get("signingValidated")
            self.assertTrue(random_signing_validated, msg="No signing rules enforced so extension should be validated.")


    def test_download_allowed_if_extension_in_allowlist(self):
        """
        If extension is in allowlist, downloadAllowed = true (regardless of global allowlist value).
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
                    ALLOWED_EXT: {}
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = Regorus(policy_file.name, self.default_rule_path)
                output = engine.eval_query(input_dict, "data.agent_extension_policy.extensions_to_download")
                result = output['result'][0]['expressions'][0]['value']
                download_allowed = result.get(ALLOWED_EXT).get("downloadAllowed")
                self.assertTrue(download_allowed,
                                msg="Extension is in allowlist so downloadAllowed should be True.")

    def test_download_allowed_depends_on_global_allowlist_rule_if_extension_not_in_allowlist(self):
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

    def test_signing_validated_depends_on_individual_signing_rule_if_present(self):
        """
        If an individual signing rule exists for the extension, signingValidated depends on the rule:
        - If individual signing rule enforced, signingValidated = true only if extension is signed.
        - If individual signing rule not enforced, signingValidated = true.
        """

    def test_signing_validated_depends_on_global_signing_rule_if_individual_rule_not_present(self):
        """
        If individual signing rule doesn't exist, signingValidated depends on global signing rule: 
        - If global signing rule enforced, signingValidated = true only if extension is signed. 
        - If global signing rule not enforced, signingValidated = true. 
        """

    def test_invalid_policy_section_should_block_all_extensions(self):
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
        with self.assertRaises(Exception, msg="Evaluating query should raise exception when rule file doesn't exist."):
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_invalid_rule_file_syntax(self):
        """Exception should be raised when we eval_query with invalid rule file syntax."""
        invalid_rule = os.path.join(data_dir, 'policy', "agent_policy_invalid.rego")
        with self.assertRaises(Exception, msg="Evaluating query should raise exception when rule file syntax is invalid"):
            engine = Regorus(self.default_policy_path, invalid_rule)
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_bad_policy_file_path(self):
        """Exception should be raised when we eval_query with invalid policy file path."""
        invalid_policy = os.path.join("agent-extension-data-invalid.json")
        with self.assertRaises(Exception, msg="Evaluating query should raise exception when policy file doesn't exist."):
            engine = Regorus(invalid_policy, self.default_rule_path)
            engine.eval_query(self.default_input, "data")

    def test_eval_query_should_raise_exception_for_invalid_policy_file_syntax(self):
        """Exception should be raised when we eval_query with bad data file contents."""
        invalid_policy = os.path.join(data_dir, 'policy', "agent-extension-data-invalid.json")
        with self.assertRaises(Exception, msg="Evaluating query should raise exception when policy file syntax is invalid."):
            engine = Regorus(invalid_policy, self.default_rule_path)
            engine.eval_query(self.default_input, "data")
