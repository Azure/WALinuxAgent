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
import json

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine, PolicyInvalidError, \
    _PolicyEngine, _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY, _DEFAULT_SIGNATURE_REQUIRED
from tests.lib.tools import patch
from azurelinuxagent.common.protocol.restapi import Extension

TEST_EXTENSION_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


class _TestPolicyBase(AgentTestCase):
    """
    Define common methods for policy engine test classes.
    """
    def setUp(self):
        AgentTestCase.setUp(self)
        self.custom_policy_path = os.path.join(self.tmp_dir, "waagent_policy.json")

        # Patch attributes to enable policy feature
        self.patch_custom_policy_path = patch('azurelinuxagent.ga.policy.policy_engine._CUSTOM_POLICY_PATH',
                                              new=self.custom_policy_path)
        self.patch_custom_policy_path.start()
        self.patch_conf_flag = patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                     return_value=True)
        self.patch_conf_flag.start()

    def tearDown(self):
        patch.stopall()
        AgentTestCase.tearDown(self)

    def _create_policy_file(self, policy):
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()


class TestPolicyEngine(_TestPolicyBase):
    """
    Test policy enablement and parsing logic for _PolicyEngine.
    """

    def test_should_raise_error_if_policy_file_is_invalid_json(self):
        incomplete_policy = """
        {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
        """
        for policy in [incomplete_policy, ""]:
            with open(self.custom_policy_path, mode='w') as policy_file:
                policy_file.write(policy)
                policy_file.flush()
            with self.assertRaises(PolicyInvalidError, msg="Invalid json in policy file should raise error."):
                _PolicyEngine()

    def test_policy_enforcement_should_be_enabled_when_policy_file_exists_and_conf_flag_true(self):
        """
        When conf flag is set to true and policy file is present at expected location, feature should be enabled.
        """
        # Create dummy policy file at the expected path to enable feature.
        self._create_policy_file({})
        engine = _PolicyEngine()
        self.assertTrue(engine.policy_enforcement_enabled,
                        msg="Conf flag is set to true so policy enforcement should be enabled.")

    def test_policy_enforcement_should_be_disabled_when_conf_flag_false_or_no_policy_file(self):

        # Test when conf flag is turned off - feature should be disabled.
        self.patch_conf_flag.stop()
        engine1 = _PolicyEngine()
        self.assertFalse(engine1.policy_enforcement_enabled,
                         msg="Conf flag is set to false and policy file missing so policy enforcement should be disabled.")

        # Turn on conf flag - feature should still be disabled, because policy file is not present.
        self.patch_conf_flag.start()
        engine2 = _PolicyEngine()
        self.assertFalse(engine2.policy_enforcement_enabled,
                         msg="Policy file is not present so policy enforcement should be disabled.")

        # Create a policy file, but turn off conf flag - feature should be disabled due to flag.
        self.patch_conf_flag.stop()
        self._create_policy_file({})
        engine3 = _PolicyEngine()
        self.assertFalse(engine3.policy_enforcement_enabled,
                         msg="Conf flag is set to false so policy enforcement should be disabled.")

    def test_should_raise_error_if_allowListedExtensionsOnly_is_string(self):
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": "True",  # Should be bool
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)
        with self.assertRaises(PolicyInvalidError, msg="String used instead of boolean, should raise error."):
            _PolicyEngine()

    def test_should_raise_error_if_signatureRequired_is_string(self):
        policy_individual = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": "False"  # Should be bool
                        }
                    }
                }
            }
        policy_global = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": "False",  # Should be bool
                    "extensions": {}
                }
            }
        for policy in [policy_individual, policy_global]:
            self._create_policy_file(policy)
            with self.assertRaises(PolicyInvalidError, msg="String used instead of boolean, should raise error."):
                _PolicyEngine()

    def test_should_raise_error_if_individual_extension_policy_is_not_dict(self):
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: ""     # Value should be a dict, not string.
                    }
                }
            }
        self._create_policy_file(policy)
        with self.assertRaises(PolicyInvalidError, msg="Individual extension policy is not a dict, should raise error."):
            _PolicyEngine()

    def test_should_raise_error_if_extensions_is_not_dict(self):
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": []    # Should be a dict
                }
            }
        self._create_policy_file(policy)
        with self.assertRaises(PolicyInvalidError, msg="List used instead of dict, should raise error."):
            _PolicyEngine()

    def test_policy_should_be_enabled_even_if_policy_file_deleted(self):
        """
        If policy file is deleted while processing a single goal state, policy should still be enabled.
        """
        self._create_policy_file({})
        engine = _PolicyEngine()
        self.assertTrue(engine.policy_enforcement_enabled)
        os.remove(self.custom_policy_path)
        self.assertTrue(engine.policy_enforcement_enabled)

    def test_should_parse_policy_successfully(self):
        """
        Values provided in custom policy should override any defaults.
        """
        policy1 = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False
                        }
                    }
                }
            }
        policy2 = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": True
                        }
                    }
                }
            }
        for expected_policy in [policy1, policy2]:
            self._create_policy_file(expected_policy)
            engine = _PolicyEngine()
            actual_policy = engine._policy
            self.assertEqual(actual_policy.get("policyVersion"), expected_policy.get("policyVersion"))

            actual_extension_policy = actual_policy.get("extensionPolicies")
            expected_extension_policy = expected_policy.get("extensionPolicies")
            self.assertEqual(actual_extension_policy.get("allowListedExtensionsOnly"), expected_extension_policy.get("allowListedExtensionsOnly"))
            self.assertEqual(actual_extension_policy.get("signatureRequired"), expected_extension_policy.get("signatureRequired"))
            self.assertEqual(actual_extension_policy.get("signatureRequired"), expected_extension_policy.get("signatureRequired"))

            actual_individual_policy = actual_extension_policy.get("extensions").get(TEST_EXTENSION_NAME)
            expected_individual_policy = expected_extension_policy.get("extensions").get(TEST_EXTENSION_NAME)
            self.assertEqual(actual_individual_policy.get("signatureRequired"), expected_individual_policy.get("signatureRequired"))


class TestExtensionPolicyEngine(_TestPolicyBase):
    """
    Test ExtensionPolicyEngine should_allow() and should_enforce_signature_validation().
    """
    def test_should_allow_and_should_not_enforce_signature_if_no_custom_policy_file(self):
        """
        When custom policy file not present, should allow all extensions and not enforce signature.
        """
        # No policy file is present - feature is disabled.
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine()
        should_allow = engine.should_allow_extension(test_extension)
        self.assertTrue(should_allow, msg="Policy feature is disabled because no custom policy file, so all extensions should be allowed.")
        should_enforce = engine.should_enforce_signature_validation(test_extension)
        self.assertFalse(should_enforce, msg="Policy feature is disabled no custom policy file, so signature should not be enforced.")

    def test_should_allow_and_should_not_enforce_signature_if_conf_flag_false(self):
        """
        When conf flag turned off, should allow all extensions and not enforce signature.
        """
        self.patch_conf_flag.stop()
        self._create_policy_file({})
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine()
        should_allow = engine.should_allow_extension(test_extension)
        self.assertTrue(should_allow, msg="Policy feature is disabled because conf flag false, so all extensions should be allowed.")
        should_enforce = engine.should_enforce_signature_validation(test_extension)
        self.assertFalse(should_enforce, msg="Policy feature is disabled because conf flag false, so signature should not be enforced.")

    def test_should_use_default_policy_if_no_custom_extension_policy_specified(self):
        """
        Test that default policy is used when custom policy file does not specify the extension policy.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy_cases = [
            {},
            {
                "policyVersion": "0.1.0"
            },
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {}
            }
        ]
        for policy in policy_cases:
            self._create_policy_file(policy)
            engine = ExtensionPolicyEngine()
            should_allow = engine.should_allow_extension(test_extension)
            self.assertEqual(should_allow, not _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY,
                             msg="Extension policy is not specified, so should use default policy.")
            should_enforce = engine.should_enforce_signature_validation(test_extension)
            self.assertEqual(should_enforce, _DEFAULT_SIGNATURE_REQUIRED,
                             msg="Extension policy is not specified, so should use default policy.")

    def test_should_allow_if_allowListedExtensionsOnly_true_and_extension_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension in list, should_allow = True.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        TEST_EXTENSION_NAME_2 = "Test.Extension.Name"
        test_extension_2 = Extension(name=TEST_EXTENSION_NAME_2)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {},
                        TEST_EXTENSION_NAME_2: {
                            "signatureRequired": False
                        }
                    }
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_allow = engine.should_allow_extension(test_extension)
        self.assertTrue(should_allow, msg="Extension is in allowlist, so should be allowed.")
        should_allow = engine.should_allow_extension(test_extension_2)
        self.assertTrue(should_allow, msg="Extension is in allowlist, so should be allowed.")

    def test_should_not_allow_if_allowListedExtensionsOnly_true_and_extension_not_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension not in list, should_allow = False.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {}  # Extension not in allowed list.
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_allow = engine.should_allow_extension(test_extension)
        self.assertFalse(should_allow,
                            msg="allowListedExtensionsOnly is true and extension is not in allowlist, so should not be allowed.")

    def test_should_allow_if_allowListedExtensionsOnly_false(self):
        """
        If allowListedExtensionsOnly is false, should_allow = True (whether extension in list or not).
        """
        # Test an extension in the allowlist, and an extension not in the allowlist. Both should be allowed.
        test_ext_in_list = Extension(name=TEST_EXTENSION_NAME)
        test_ext_not_in_list = Extension(name="Random.Ext")
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": False,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False
                        }
                    }
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        self.assertTrue(engine.should_allow_extension(test_ext_in_list),
                        msg="allowListedExtensionsOnly is false, so extension should be allowed.")
        self.assertTrue(engine.should_allow_extension(test_ext_not_in_list),
                        msg="allowListedExtensionsOnly is false, so extension should be allowed.")

    def test_should_enforce_signature_if_individual_signatureRequired_true(self):
        """
        If signatureRequired is true for individual extension, should_enforce_signature_validation = True (whether global signatureRequired is true or false).
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        global_signature_rule_cases = [True, False]
        for global_rule in global_signature_rule_cases:
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": False,
                        "signatureRequired": global_rule,
                        "extensions": {
                            TEST_EXTENSION_NAME: {
                                "signatureRequired": True
                            }
                        }
                    }
                }
            self._create_policy_file(policy)
            engine = ExtensionPolicyEngine()
            should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
            self.assertTrue(should_enforce_signature,
                            msg="Individual signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_individual_signatureRequired_false(self):
        """
        If signatureRequired is false for individual extension policy, should_enforce_signature_validation = False (whether global signatureRequired is true or false).
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        global_signature_rule_cases = [True, False]
        for global_rule in global_signature_rule_cases:
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": False,
                        "signatureRequired": global_rule,
                        "extensions": {
                            TEST_EXTENSION_NAME: {
                                "signatureRequired": False,
                            }
                        }
                    }
                }
            self._create_policy_file(policy)
            engine = ExtensionPolicyEngine()
            should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
            self.assertFalse(should_enforce_signature,
                                msg="Individual signatureRequired policy is false, so signature should be not enforced.")

    def test_should_enforce_signature_if_global_signatureRequired_true_and_no_individual_policy(self):
        """
        If signatureRequired is true globally and no individual extension signature policy, should_enforce_signature_validation = True.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
        self.assertTrue(should_enforce_signature,
                        msg="Global signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_global_signatureRequired_false_and_no_individual_policy(self):
        """
        If signatureRequired is false globally and no individual extension signature policy, should_enforce_signature_validation = False.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
        self.assertFalse(should_enforce_signature,
                            msg="Global signatureRequired policy is false, so signature should not be enforced.")

    def test_should_enforce_signature_if_global_signatureRequired_true_and_individual_signatureRequired_not_specified(self):
        """
        If individual policy is present, but signatureRequired is not specified for that policy, use global signatureRequired.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "extensions": {
                        TEST_EXTENSION_NAME: {}
                    }
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
        self.assertTrue(should_enforce_signature,
                            msg="Individual signatureRequired policy is not set, so should use global policy and enforce signature.")

    def test_should_not_enforce_signature_if_global_signatureRequired_false_and_individual_signatureRequired_not_specified(self):
        """
        If individual policy is present, but signatureRequired is not specified for that policy, use global signatureRequired.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {}
                    }
                }
            }
        self._create_policy_file(policy)
        engine = ExtensionPolicyEngine()
        should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
        self.assertFalse(should_enforce_signature,
                            msg="Individual signatureRequired policy is not set, so should use global policy and enforce signature.")
    def test_extension_name_in_policy_should_be_case_insensitive(self):
        """
        Extension name is allowed to be any case. Test that should_allow() and should_enforce_signature_validation() return expected
        results, even when the extension name does not match the case of the name specified in policy.
        """
        ext_name_in_policy = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
        for ext_name_to_test in [
            "MicrOsoft.aZure.activedirectory.aaDsShloginFORlinux",
            "microsoft.azure.activedirectory.aadsshloginforlinux"
        ]:
            test_extension = Extension(name=ext_name_to_test)
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "signatureRequired": False,
                        "extensions": {
                            ext_name_in_policy: {
                                "signatureRequired": True
                            }
                        }
                    }
                }

            self._create_policy_file(policy)
            engine = ExtensionPolicyEngine()
            should_allow = engine.should_allow_extension(test_extension)
            should_enforce_signature = engine.should_enforce_signature_validation(test_extension)
            self.assertTrue(should_allow,
                            msg="Extension should have been found in allowlist regardless of extension name case.")
            self.assertTrue(should_enforce_signature,
                            msg="Individual signatureRequired policy should have been found and used, regardless of extension name case.")