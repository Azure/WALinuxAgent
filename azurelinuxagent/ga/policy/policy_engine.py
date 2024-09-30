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
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.osutil.factory import get_osutil


# Customer-defined policy is expected to be located at this path.
# If there is no file at this path, default policy will be used.
_CUSTOM_POLICY_PATH = get_osutil().get_custom_policy_file_path()

# Default policy values to be used when no custom policy is present.
_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
_DEFAULT_SIGNATURE_REQUIRED = False


class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """


class PolicyInvalidError(AgentError):
    """
    Error raised if user-provided policy is invalid.
    """
    def __init__(self, msg, inner=None):
        msg = "Customer-provided policy file ('{0}') is invalid, please correct the policy: {1}".format(_CUSTOM_POLICY_PATH, msg)
        super(PolicyInvalidError, self).__init__(msg, inner)


class _PolicyEngine(object):
    """
    Implements base policy engine API.
    """
    def __init__(self):
        if not self.is_policy_enforcement_enabled():
            self._log_policy_event(msg="Policy enforcement is not enabled.")
            return

        self._policy = self.__get_policy()

    @staticmethod
    def _log_policy_event(msg, is_success=True, op=WALAEventOperation.Policy, send_event=True):
        """
        Log information to console and telemetry.
        """
        if is_success:
            logger.info(msg)
        else:
            logger.error(msg)
        if send_event:
            add_event(op=op, message=msg, is_success=is_success, log_event=False)

    @staticmethod
    def is_policy_enforcement_enabled():
        """
        Policy will be enabled if (1) policy file exists at _CUSTOM_POLICY_PATH and (2) the conf flag "Debug.EnableExtensionPolicy" is true.
        Caller function should check this before performing any operations.
        """
        # Policy should only be enabled if conf flag is true AND policy file is present.
        policy_file_exists = os.path.exists(_CUSTOM_POLICY_PATH)
        return conf.get_extension_policy_enabled() and policy_file_exists

    def __get_policy(self):
        """
        Load policy JSON object from policy file (CUSTOM_POLICY_PATH), return as a dict.

        Note that we should only call this function after validating that CUSTOM_POLICY_PATH exists (this is currently
        done in __init__).
        """
        # TODO: Add schema validation for custom policy file and raise relevant error message to user.
        with open(_CUSTOM_POLICY_PATH, 'r') as f:        # Open file in read-only mode.
            self._log_policy_event("Custom policy file found at {0}. Using custom policy.".format(_CUSTOM_POLICY_PATH))
            try:
                custom_policy = json.load(f)
            except Exception as ex:
                msg = "policy file does not conform to valid json syntax"
                raise PolicyInvalidError(msg=msg, inner=ex)
            return self.__parse_policy(custom_policy)

    @staticmethod
    def __parse_policy(custom_policy):
        """
        Return a policy combining the default and custom_policy. Any attributes provided in the custom policy
        override default values used in the template. If attribute is not provided, default is used.

        The value of the "extensions" attribute is a case-folded dict. CRP allows extensions to be any case, so we use
        case-folded dict to allow for case-insensitive lookup of individual extension policies.

        The expected custom policy format is:
         {
            "policyVersion": str,
            "extensionPolicies": {
                "allowListedExtensionsOnly": bool,
                "signatureRequired": bool,
                "extensions": {
                    "<extensionName1>": {
                        "signatureRequired": bool
                    }
                }
            }
        }
        """
        # We use the default policy as a template, and replace any attributes provided in the custom policy.
        template = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY,
                    "signatureRequired": _DEFAULT_SIGNATURE_REQUIRED,
                    "extensions": {}
                }
            }

        extension_policies = custom_policy.get("extensionPolicies")
        if extension_policies is not None:
            # Validate and update template with global allowlist policy
            allowlist_policy = extension_policies.get("allowListedExtensionsOnly")
            if allowlist_policy is not None:
                if not isinstance(allowlist_policy, bool):
                    raise PolicyInvalidError(
                        "invalid type {0} for attribute 'allowListedExtensionsOnly', please change to bool."
                        .format(type(allowlist_policy).__name__))
                template["extensionPolicies"]["allowListedExtensionsOnly"] = allowlist_policy

            # Validate and update template with global signature policy
            signature_policy = extension_policies.get("signatureRequired")
            if signature_policy is not None:
                if not isinstance(signature_policy, bool):
                    raise PolicyInvalidError(
                        "invalid type {0} for attribute 'signatureRequired', please change to bool"
                        .format(type(signature_policy).__name__))
                template["extensionPolicies"]["signatureRequired"] = signature_policy

            # Parse individual extension policies
            extensions = extension_policies.get("extensions")
            if extensions is not None:
                for ext_name, ext_policy in extensions.items():
                    if ext_policy is not None:
                        individual_signing_policy = ext_policy.get("signatureRequired")
                        if individual_signing_policy is not None:
                            if not isinstance(individual_signing_policy, bool):
                                raise PolicyInvalidError(
                                    "invalid type {0} for attribute 'signatureRequired', please change to bool."
                                    .format(type(individual_signing_policy).__name__))
                        else:
                            # If individual extension is present but signature policy not specified, use global policy.
                            individual_signing_policy = template.get("extensionPolicies").get("signatureRequired")

                        # Build individual extension policy and add to template.
                        policy_to_add = {
                            "signatureRequired": individual_signing_policy
                        }
                        template["extensionPolicies"]["extensions"][ext_name] = policy_to_add

                # Convert "extensions" to a case-folded dict for case-insensitive lookup
                case_folded_extension_dict = _CaseFoldedDict.from_dict(template["extensionPolicies"]["extensions"])
                template["extensionPolicies"]["extensions"] = case_folded_extension_dict

        return template


class ExtensionPolicyEngine(_PolicyEngine):

    def should_allow_extension(self, extension_to_check):
        """
        Return whether we should allow extension download based on policy.
        extension_to_check is expected to be an Extension object.

        If policy feature not enabled, return True.
        If allowListedExtensionsOnly=true, return true only if extension present in "extensions" allowlist.
        If allowListedExtensions=false, return true always.
        """
        if not self.is_policy_enforcement_enabled():
            return True

        allow_listed_extension_only = self._policy.get("extensionPolicies").get("allowListedExtensionsOnly")
        extension_allowlist = self._policy.get("extensionPolicies").get("extensions")

        should_allow = not allow_listed_extension_only or extension_allowlist.get(extension_to_check.name) is not None
        return should_allow

    def should_enforce_signature_validation(self, extension_to_check):
        """
        Return whether we should enforce signature based on policy.
        extension_to_check is expected to be an Extension object.

        If policy feature not enabled, return False.
        Individual policy takes precedence over global - if individual signing policy present, return true/false based on
        individual policy. Else, return true/false based on global policy.
        """
        if not self.is_policy_enforcement_enabled():
            return False

        global_signature_required = self._policy.get("extensionPolicies").get("signatureRequired")
        extension_dict = self._policy.get("extensionPolicies").get("extensions")
        extension_individual_policy = extension_dict.get(extension_to_check.name)
        if extension_individual_policy is None:
            return global_signature_required
        else:
            individual_signature_required = extension_individual_policy.get("signatureRequired")
            return individual_signature_required

    # TODO: Consider adding a function should_download_extension() combining should_allow_extension() and
    # should_enforce_signature_validation(), such that caller function only needs to make one call.
