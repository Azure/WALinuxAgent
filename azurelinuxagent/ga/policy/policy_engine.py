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
from azurelinuxagent.common.osutil.default import DefaultOSUtil


# Customer-defined policy is expected to be located at this path.
# If there is no file at this path, default policy will be used.
CUSTOM_POLICY_PATH = DefaultOSUtil().get_custom_policy_file_path()

# Default policy values to be used when no custom policy is present.
_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
_DEFAULT_SIGNATURE_REQUIRED = False


class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """
    # TODO: split into two error classes for internal/dev errors and user errors.
    def __init__(self, msg=None, inner=None, code=-1):
        super(PolicyError, self).__init__(msg, inner)
        self.code = code


class _PolicyEngine(object):
    """
    Implements base policy engine API.
    """
    def __init__(self):
        if not self.is_policy_enforcement_enabled():
            self._log_policy_event(msg="Policy enforcement is not enabled.")
            return

        self.policy = self.__get_policy()

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
        Policy will be enabled if (1) policy file exists at CUSTOM_POLICY_PATH and (2) the conf flag "Debug.EnableExtensionPolicy" is true.
        Caller function should check this before performing any operations.
        """
        # Policy should only be enabled if conf flag is true AND policy file is present.
        policy_file_exists = os.path.exists(CUSTOM_POLICY_PATH)
        return conf.get_extension_policy_enabled() and policy_file_exists

    def __get_policy(self):
        """
        Check if custom policy exists at CUSTOM_POLICY_PATH, load JSON object and return as a dict.
        Return default policy if no policy exists.
        """
        # TODO: Add schema validation for custom policy file and raise relevant error message to user.
        if os.path.exists(CUSTOM_POLICY_PATH):
            self._log_policy_event("Custom policy found at {0}. Using custom policy.".format(CUSTOM_POLICY_PATH))
            with open(CUSTOM_POLICY_PATH, 'r') as f:        # Open file in read-only mode.
                custom_policy = json.load(f)
                return self.__parse_policy(custom_policy)
        else:
            self._log_policy_event("No custom policy found at {0}. Using default policy.".format(CUSTOM_POLICY_PATH))
            return self.__parse_policy({})  # Return default policy

    @staticmethod
    def __parse_policy(custom_policy):
        """
        Update default policy template with provided custom policy.
        Any attributes provided in custom policy override default values in template.
        If an attribute is not provided in custom policy, default is used.

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
                    raise ValueError(
                        "Invalid type {0} for attribute 'allowListedExtensionsOnly' in policy. Expected bool"
                        .format(type(allowlist_policy).__name__))
                template["extensionPolicies"]["allowListedExtensionsOnly"] = allowlist_policy

            # Validate and update template with global signature policy
            signature_policy = extension_policies.get("signatureRequired")
            if signature_policy is not None:
                if not isinstance(signature_policy, bool):
                    raise ValueError(
                        "Invalid type {0} for attribute 'allowListedExtensionsOnly' in policy. Expected bool"
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
                                raise ValueError(
                                    "Invalid type {0} for attribute 'signatureRequired' in policy. Expected bool"
                                    .format(type(individual_signing_policy).__name__))
                        else:
                            # If individual extension is present but signature policy not specified, use global policy.
                            individual_signing_policy = template.get("extensionPolicies").get("signatureRequired")

                        # Build individual extension policy and add to template.
                        policy_to_add = {
                            "signatureRequired": individual_signing_policy
                        }

                        template["extensionPolicies"]["extensions"][ext_name] = policy_to_add

                case_folded_extension_dict = _CaseFoldedDict.from_dict(template["extensionPolicies"]["extensions"])
                template["extensionPolicies"]["extensions"] = case_folded_extension_dict

        return template


class ExtensionPolicyEngine(_PolicyEngine):

    def __init__(self):
        super(ExtensionPolicyEngine, self).__init__()
        if not self.is_policy_enforcement_enabled():
            return

        extension_policy = self.policy.get("extensionPolicies", {})
        self.extension_policy = extension_policy

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

        allow_listed_extension_only = self.extension_policy.get("allowListedExtensionsOnly")
        extension_allowlist = self.extension_policy.get("extensions")

        # CRP allows extension names to be any case. Extension names in policy are lowercase, so we use lowercase here.
        should_allow = not allow_listed_extension_only or extension_allowlist.get(extension_to_check.name.lower()) is not None
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

        extension_dict = self.extension_policy.get("extensions")
        global_signature_required = self.extension_policy.get("signatureRequired")
        extension_individual_policy = extension_dict.get(extension_to_check.name.lower())
        if extension_individual_policy is None:
            return global_signature_required
        else:
            individual_signature_required = extension_individual_policy.get("signatureRequired")
            return individual_signature_required

    # TODO: Consider adding a function should_download_extension() combining should_allow_extension() and
    # should_enforce_signature_validation(), such that caller function only needs to make one call.
