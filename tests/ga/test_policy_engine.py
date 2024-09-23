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
from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine
from tests.lib.tools import patch, data_dir
from azurelinuxagent.common.protocol.restapi import Extension

TEST_EXTENSION_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


class TestExtensionPolicyEngine(AgentTestCase):
    def setUp(self):
        self.custom_policy_path = os.path.join(data_dir, 'policy',
                                               "waagent_policy.json")  # Path where we should create custom policy files for tests.

        # Patch attributes to enable policy feature
        self.patch_custom_policy_path = patch('azurelinuxagent.ga.policy.policy_engine.CUSTOM_POLICY_PATH',
                                              new=self.custom_policy_path)
        self.patch_custom_policy_path.start()
        self.patch_conf_flag = patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                     return_value=True)
        self.patch_conf_flag.start()

        AgentTestCase.setUp(self)

    def tearDown(self):
        # Clean up any custom policy file we created
        if os.path.exists(self.custom_policy_path):
            os.remove(self.custom_policy_path)
        patch.stopall()
        AgentTestCase.tearDown(self)

    def test_policy_enforcement_should_be_enabled(self):
        """
        When conf flag is set to true and policy file is present at expected location, feature should be enabled.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
            # Create dummy policy file at the expected path to enable feature.
            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump({}, policy_file, indent=4)
                policy_file.flush()
                engine = ExtensionPolicyEngine(test_extension)
                self.assertTrue(engine.is_policy_enforcement_enabled(),
                                msg="Conf flag is set to true so policy enforcement should be enabled.")

    def test_policy_enforcement_should_be_disabled(self):
        self.patch_conf_flag.stop()  # Turn off the policy feature enablement
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        self.assertFalse(engine.is_policy_enforcement_enabled(),
                         msg="Conf flag is set to false so policy enforcement should be disabled.")

    def test_should_allow_and_should_not_enforce_signature_for_default_policy(self):
        """
        Default policy should allow all extensions and not enforce signature.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow, msg="Default policy should allow all extensions.")
        should_enforce = engine.should_enforce_signature()
        self.assertFalse(should_enforce, msg="Default policy should not enforce extension signature.")

    def test_should_allow_if_allowListedExtensionsOnly_true_and_extension_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension in list, should_allow = True.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False,
                            "signingPolicy": {},
                            "runtimePolicy": {}
                        }
                    }
                }
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
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
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
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
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine1 = ExtensionPolicyEngine(test_ext_in_list)
            self.assertTrue(engine1.should_allow_extension(),
                            msg="allowListedExtensionsOnly is false, so extension should be allowed.")
            engine2 = ExtensionPolicyEngine(test_ext_not_in_list)
            self.assertTrue(engine2.should_allow_extension(),
                            msg="allowListedExtensionsOnly is false, so extension should be allowed.")

    def test_should_enforce_signature_if_individual_enforceSignature_true(self):
        """
        If signatureRequired is true for individual extension, should_enforce_signature = True (whether global signatureRequired is true or false).
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

            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = ExtensionPolicyEngine(test_extension)
                should_enforce_signature = engine.should_enforce_signature()
                self.assertTrue(should_enforce_signature,
                                msg="Individual signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_individual_enforceSignature_false(self):
        """
        If signatureRequired is false for individual extension policy, should_enforce_signature = False (whether global signatureRequired is true or false).
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

            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = ExtensionPolicyEngine(test_extension)
                should_enforce_signature = engine.should_enforce_signature()
                self.assertFalse(should_enforce_signature,
                                 msg="Individual signatureRequired policy is false, so signature should be not enforced.")

    def test_should_enforce_signature_if_global_enforceSignature_true_and_no_individual_policy(self):
        """
        If signatureRequired is true globally and no individual extension signature policy, should_enforce_signature = True.
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
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_enforce_signature = engine.should_enforce_signature()
            self.assertTrue(should_enforce_signature,
                            msg="Global signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_global_enforceSignature_false_and_no_individual_policy(self):
        """
        If signatureRequired is false globally and no individual extension signature policy, should_enforce_signature = False.
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
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_enforce_signature = engine.should_enforce_signature()
            self.assertFalse(should_enforce_signature,
                             msg="Global signatureRequired policy is false, so signature should not be enforced.")

    def test_should_enforce_signature_if_no_custom_policy_present(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_enforce_signature = engine.should_enforce_signature()
        self.assertFalse(should_enforce_signature,
                         msg="No custom policy is present, so use default policy. Should not enforce signature.")

    def test_should_allow_if_no_custom_policy_present(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow,
                        msg="No custom policy is present, so use default policy. Should allow all extensions.")

    def test_should_raise_error_if_allowListedExtensionsOnly_is_string(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": "True",  # Should be bool
                    "signatureRequired": False,
                    "extensions": {}
                }
            }

        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            with self.assertRaises(ValueError, msg="String used instead of boolean, should raise error."):
                engine = ExtensionPolicyEngine(test_extension)
                engine.should_allow_extension()

    def test_should_raise_error_if_signatureRequired_is_string(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
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
            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with self.assertRaises(ValueError, msg="String used instead of boolean, should raise error."):
                    engine = ExtensionPolicyEngine(test_extension)
                    engine.should_enforce_signature()

    def test_should_allow_if_extension_policy_section_missing(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0"
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
            self.assertTrue(should_allow)

    def test_should_allow_if_policy_disabled(self):
        self.patch_conf_flag.stop()  # Turn off the policy feature enablement
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow,
                        msg="Policy feature is disabled, so all extensions should be allowed.")

    def test_should_not_enforce_signature_if_policy_disabled(self):
        self.patch_conf_flag.stop()  # Turn off the policy feature enablement
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_enforce_signature = engine.should_enforce_signature()
        self.assertFalse(should_enforce_signature,
                         msg="Policy feature is disabled, so signature should not be enforced.")

    def test_should_handle_lowercase(self):
        pass