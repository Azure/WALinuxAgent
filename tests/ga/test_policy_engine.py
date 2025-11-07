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

from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine, InvalidPolicyError, \
    _PolicyEngine, _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY, _DEFAULT_SIGNATURE_REQUIRED
from tests.lib.tools import AgentTestCase, MagicMock, patch

TEST_EXTENSION_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


class _TestPolicyBase(AgentTestCase):
    """
    Define common methods for policy engine test classes.
    """
    def setUp(self):
        AgentTestCase.setUp(self)
        self.policy_path = os.path.join(self.tmp_dir, "waagent_policy.json")

        # Patch attributes to enable policy feature
        self.patch_policy_path = patch('azurelinuxagent.common.conf.get_policy_file_path',
                                       return_value=str(self.policy_path))
        self.patch_policy_path.start()
        self.patch_conf_flag = patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                     return_value=True)
        self.patch_conf_flag.start()
    
        self.patch_is_cvm = patch('azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo.is_confidential_vm', return_value=True)
        self.mock_is_cvm = self.patch_is_cvm.start()

        self.goal_state_history = MagicMock()
        self.goal_state_history.save_to_history = MagicMock(return_value=None)

    def tearDown(self):
        patch.stopall()
        AgentTestCase.tearDown(self)

    def _create_policy_file(self, policy):
        with open(self.policy_path, mode='w') as policy_file:
            if isinstance(policy, dict):
                json.dump(policy, policy_file, indent=4)
            else:
                policy_file.write(policy)
            policy_file.flush()

    def _run_test_cases_should_fail_to_parse(self, cases, assert_msg):
        """
        Cases should be a list of policies.
        For each policy in the list, we create a policy file, initialize policy engine, and assert that InvalidPolicyError
        is raised.
        """
        for policy in cases:
            self._create_policy_file(policy)
            msg = "invalid policy should not have parsed successfully: {0}.\nPolicy: \n{1}".format(assert_msg, policy)
            engine = _PolicyEngine()
            with self.assertRaises(InvalidPolicyError, msg=msg):
                engine.update_policy(self.goal_state_history)


class TestPolicyEngine(_TestPolicyBase):
    """
    Test policy enablement and parsing logic for _PolicyEngine.
    """
    def test_policy_enforcement_should_be_enabled_when_policy_file_exists_and_conf_flag_true(self):
        """
        When conf flag is set to true and policy file is present at expected location, feature should be enabled.
        """
        # Create policy file with empty policy object at the expected path to enable feature.
        self._create_policy_file(
        {
            "policyVersion": "0.0.1"
        })
        engine = _PolicyEngine()
        engine.update_policy(self.goal_state_history)
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

    def test_should_parse_policy_successfully(self):
        """
        Values provided in custom policy should override any defaults.
        """
        policy1 = \
            {
                "policyVersion": "0.0.1",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False,
                            "runtimePolicy": True
                        }
                    }
                }
            }
        policy2 = \
            {
                "policyVersion": "0.0.1",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": True,
                            "runtimePolicy": [ True, None, { "bar": "baz" } ]
                        }
                    }
                }
            }
        for expected_policy in [policy1, policy2]:
            self._create_policy_file(expected_policy)
            engine = _PolicyEngine()
            engine.update_policy(self.goal_state_history)
            actual_policy = engine._policy
            self.assertEqual(actual_policy.get("policyVersion"), expected_policy.get("policyVersion"))

            actual_extension_policy = actual_policy.get("extensionPolicies")
            expected_extension_policy = expected_policy.get("extensionPolicies")
            self.assertEqual(actual_extension_policy.get("allowListedExtensionsOnly"), expected_extension_policy.get("allowListedExtensionsOnly"))
            self.assertEqual(actual_extension_policy.get("signatureRequired"), expected_extension_policy.get("signatureRequired"))

            actual_individual_policy = actual_extension_policy.get("extensions").get(TEST_EXTENSION_NAME)
            expected_individual_policy = expected_extension_policy.get("extensions").get(TEST_EXTENSION_NAME)
            self.assertEqual(actual_individual_policy.get("signatureRequired"), expected_individual_policy.get("signatureRequired"))
            self.assertEqual(actual_individual_policy.get("runtimePolicy"), expected_individual_policy.get("runtimePolicy"))

    def test_it_should_verify_policy_version_is_required(self):
        self._create_policy_file({
                "extensionPolicies": {}
            })
        engine = _PolicyEngine()
        with self.assertRaises(InvalidPolicyError):
            engine.update_policy(self.goal_state_history)

    def test_it_should_accept_partially_specified_policy_versions(self):
        for policy_version in ['0', '0.1', '0.1.0']:
            self._create_policy_file({
                    "policyVersion": policy_version,
                })
            engine = _PolicyEngine()
            engine.update_policy(self.goal_state_history)
            self.assertEqual(policy_version, engine._policy["policyVersion"])

    def test_should_raise_error_if_policy_file_is_invalid_json(self):
        cases = [
            '''
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
            ''',
            "",
            " ",
            "policy",
            '''
            { not_a_string: ""}
            '''
        ]
        self._run_test_cases_should_fail_to_parse(cases, "not a valid json")

    def test_should_raise_error_for_invalid_policy_version(self):
        cases = [
            {"policyVersion": "1.2.a"},
            {"policyVersion": 0},
            {"policyVersion": None}
        ]
        self._run_test_cases_should_fail_to_parse(cases, "policy version invalid")

    def test_should_raise_error_for_unsupported_policy_version(self):
        cases = [
            {"policyVersion": "9.9.9"},
            {"policyVersion": "9"}
        ]
        self._run_test_cases_should_fail_to_parse(cases, "agent does not support policy version")

    def test_should_raise_error_if_extensions_policy_is_not_dict(self):
        cases = [
            {
                "extensionPolicies": ""
            },
            {
                "extensionPolicies": None
            }
        ]
        self._run_test_cases_should_fail_to_parse(cases, "extensionPolicies is not a dict")

    def test_should_raise_error_if_allowListedExtensionsOnly_is_not_bool(self):
        cases = [
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": "True",  # Should be bool
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        ]
        self._run_test_cases_should_fail_to_parse(cases, "allowListedExtensionsOnly is not a bool")

    def test_should_raise_error_if_signatureRequired_is_not_bool(self):
        cases = [
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
            },
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": "False",  # Should be bool
                    "extensions": {}
                }
            }
        ]
        self._run_test_cases_should_fail_to_parse(cases, "signatureRequired is not a bool")

    def test_should_raise_error_if_extensions_is_not_dict(self):
        cases = [
            {
                "extensionPolicies": {
                    "extensions": []
                }
            },
            {
                "extensionPolicies": {
                    "extensions": 0
                }
            },
            {
                "extensionPolicies": {
                    "extensions": None
                }
            }
        ]
        self._run_test_cases_should_fail_to_parse(cases, "'extensions' is not a dict")

    def test_should_raise_error_if_individual_extension_policy_is_not_dict(self):
        cases = [
            {
                "extensionPolicies": {
                    "extensions": {
                        "Ext.Name": 0
                    }
                }
            },
            {
                "extensionPolicies": {
                    "extensions": {
                        "Ext.Name": []
                    }
                }
            }
        ]
        self._run_test_cases_should_fail_to_parse(cases, "individual extension policy is not a dict")

    def test_should_raise_error_for_unrecognized_attribute(self):
        # All cases below have either a typo or a random additional attribute.
        cases = [
            {"policyVerion": "0.0.1"},
            {"extentionPolicies": {}},
            {"extensionPolicies": {
                "signingRequired": {}
            }},
            {"extensionPolicies": {
                "extensions": {
                    TEST_EXTENSION_NAME: {
                        "randomAttribute": ""
                    }
                }
            }}
        ]
        self._run_test_cases_should_fail_to_parse(cases, "unrecognized attribute in policy")

    def test_should_raise_error_for_signatureRequired_on_non_cvm(self):
        self.mock_is_cvm.return_value = False   # Running on a non-CVM
        cases = [
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "extensions": {}
                }
            },
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": True
                        }
                    }
                }
            },
        ]
        self._run_test_cases_should_fail_to_parse(cases, "'signatureRequired' only supported on confidential virtual machines")


class TestExtensionPolicyEngine(_TestPolicyBase):
    """
    Test ExtensionPolicyEngine should_allow() and should_enforce_signature_validation().
    """
    def test_should_allow_and_should_not_enforce_signature_if_no_custom_policy_file(self):
        """
        When custom policy file not present, should allow all extensions and not enforce signature.
        """
        # No policy file is present - feature is disabled.
        engine = ExtensionPolicyEngine()
        should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME)
        self.assertTrue(should_allow, msg="Policy feature is disabled because no policy file present, so all extensions should be allowed.")
        should_enforce = engine.should_enforce_signature_validation(TEST_EXTENSION_NAME)
        self.assertFalse(should_enforce, msg="Policy feature is disabled because no policy file present, so signature should not be enforced.")

    def test_should_allow_and_should_not_enforce_signature_if_conf_flag_false(self):
        """
        When conf flag turned off, should allow all extensions and not enforce signature.
        """
        self.patch_conf_flag.stop()
        self._create_policy_file({})
        engine = ExtensionPolicyEngine()
        should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME)
        self.assertTrue(should_allow, msg="Policy feature is disabled because conf flag false, so all extensions should be allowed.")
        should_enforce = engine.should_enforce_signature_validation(TEST_EXTENSION_NAME)
        self.assertFalse(should_enforce, msg="Policy feature is disabled because conf flag false, so signature should not be enforced.")

    def test_should_use_default_policy_if_no_extension_policy_specified(self):
        """
        Test that default policy is used when policy file does not specify the extension policy.
        """
        policy_cases = [
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
            should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME)
            self.assertEqual(should_allow, not _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY,
                             msg="Extension policy is not specified, so should use default policy.")
            should_enforce = engine.should_enforce_signature_validation(TEST_EXTENSION_NAME)
            self.assertEqual(should_enforce, _DEFAULT_SIGNATURE_REQUIRED,
                             msg="Extension policy is not specified, so should use default policy.")

    def test_should_allow_if_allowListedExtensionsOnly_true_and_extension_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension in list, should_allow = True.
        """
        TEST_EXTENSION_NAME_2 = "Test.Extension.Name"
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
        should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME)
        self.assertTrue(should_allow, msg="Extension is in allowlist, so should be allowed.")
        should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME_2)
        self.assertTrue(should_allow, msg="Extension is in allowlist, so should be allowed.")

    def test_should_not_allow_if_allowListedExtensionsOnly_true_and_extension_not_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension not in list, should_allow = False.
        """
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
        engine.update_policy(self.goal_state_history)
        should_allow = engine._should_allow_extension(TEST_EXTENSION_NAME)
        self.assertFalse(should_allow,
                            msg="allowListedExtensionsOnly is true and extension is not in allowlist, so should not be allowed.")

    def test_should_allow_if_allowListedExtensionsOnly_false(self):
        """
        If allowListedExtensionsOnly is false, should_allow = True (whether extension in list or not).
        """
        # Test an extension in the allowlist, and an extension not in the allowlist. Both should be allowed.
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
        self.assertTrue(engine._should_allow_extension(TEST_EXTENSION_NAME),
                        msg="allowListedExtensionsOnly is false, so extension should be allowed.")
        self.assertTrue(engine._should_allow_extension("Random.Ext"),
                        msg="allowListedExtensionsOnly is false, so extension should be allowed.")

    def test_should_enforce_signature_if_individual_signatureRequired_true(self):
        """
        If signatureRequired is true for individual extension, should_enforce_signature_validation = True (whether global signatureRequired is true or false).
        """
        for global_rule in [True, False]:
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
            engine.update_policy(self.goal_state_history)
            should_enforce_signature = engine.should_enforce_signature_validation(TEST_EXTENSION_NAME)
            self.assertTrue(should_enforce_signature,
                            msg="Individual signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_individual_signatureRequired_false(self):
        """
        If signatureRequired is false for individual extension policy, should_enforce_signature_validation = False (whether global signatureRequired is true or false).
        """
        for global_rule in [True, False]:
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
            should_enforce_signature = engine.should_enforce_signature_validation(TEST_EXTENSION_NAME)
            self.assertFalse(should_enforce_signature,
                                msg="Individual signatureRequired policy is false, so signature should be not enforced.")

    def test_should_use_global_signatureRequired_when_an_individual_policy_is_not_specified(self):
        for global_policy in [True, False]:
            extensions_test_cases = [
                None,
                {},
                {
                    TEST_EXTENSION_NAME: {}
                },
                {
                    TEST_EXTENSION_NAME: {
                        "runtimePolicy": "an arbitrary object"
                    }
                }
            ]
            for extensions in extensions_test_cases:
                policy = {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "signatureRequired": global_policy,
                    }
                }
                if extensions is not None:
                    policy["extensionPolicies"]["extensions"] = extensions

                self._create_policy_file(policy)
                engine = ExtensionPolicyEngine()
                engine.update_policy(self.goal_state_history)

                self.assertEqual(
                    global_policy,
                    engine.should_enforce_signature_validation(TEST_EXTENSION_NAME),
                    "The global signatureRequired ({0}) should have been used. Policy:\n{1}".format(global_policy, policy))

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
            engine.update_policy(self.goal_state_history)
            should_allow = engine._should_allow_extension(ext_name_to_test)
            should_enforce_signature = engine.should_enforce_signature_validation(ext_name_to_test)
            self.assertTrue(should_allow,
                            msg="Extension should have been found in allowlist regardless of extension name case.")
            self.assertTrue(should_enforce_signature,
                            msg="Individual signatureRequired policy should have been found and used, regardless of extension name case.")
