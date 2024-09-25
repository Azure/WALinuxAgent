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

# Customer-defined policy is expected to be located at this path.
# If there is no file at this path, default policy will be used.
CUSTOM_POLICY_PATH = "/etc/waagent_policy.json"
# Default policy values to be used when no custom policy is present.
DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
DEFAULT_SIGNATURE_REQUIRED = False


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
            self._log_policy(msg="Policy enforcement is not enabled.")
            return

        self.policy = self.__get_policy()


    @classmethod
    def _log_policy(cls, msg, is_success=True, op=WALAEventOperation.Policy, send_event=True):
        """
        Log information to console and telemetry.
        """
        if is_success:
            logger.info(msg)
        else:
            logger.error(msg)
        if send_event:
            add_event(op=op, message=msg, is_success=is_success)

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
        Return {} if no policy exists.
        The expected policy format is:
         {
            "policyVersion": str,
            "extensionPolicies": {
                "allowListedExtensionsOnly": bool,
                "signatureRequired": bool,
                "signingPolicy": dict,
                "extensions": {
                    "<extensionName1>": {
                        "signatureRequired": bool,
                        "signingPolicy": dict,
                        "runtimePolicy": dict
                    }
                }
            }
        }
        """
        if os.path.exists(CUSTOM_POLICY_PATH):
            self._log_policy("Custom policy found at {0}. Using custom policy.".format(CUSTOM_POLICY_PATH))
            with open(CUSTOM_POLICY_PATH, 'r') as f:        # Open file in read-only mode.
                custom_policy = json.load(f)
                return custom_policy
        else:
            self._log_policy("No custom policy found at {0}. Using default policy.".format(CUSTOM_POLICY_PATH))
            return {}


class ExtensionPolicyEngine(_PolicyEngine):

    def __init__(self, extension_to_check):
        self.extension_to_check = extension_to_check    # each instance is tied to an extension.
        super(ExtensionPolicyEngine, self).__init__()
        if not self.is_policy_enforcement_enabled():
            return

        extension_policy = self.policy.get("extensionPolicies", {})
        # CRP allows extension names to be any case. We use a case-folded dict to do a case-insensitive query of the allowlist.
        # The rest of the policy remains case-sensitive, so we only replace the "extensions" dict with a case-folded dict,
        # if it exists.
        if extension_policy.get("extensions") is not None:
            case_folded_extension_dict = _CaseFoldedDict.from_dict(extension_policy.get("extensions"))
            self.policy["extensionPolicies"]["extensions"].update(case_folded_extension_dict)

        self.extension_policy = extension_policy

    def should_allow_extension(self):
        """
        Return whether we should allow extension download based on policy.

        If policy feature not enabled, return True.
        If allowListedExtensionsOnly=true, return true only if extension present in "extensions" allowlist.
        If allowListedExtensions=false, return true always.
        """
        if not self.is_policy_enforcement_enabled():
            return True

        allow_listed_extension_only = self.extension_policy.get("allowListedExtensionsOnly", DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY)
        if not isinstance(allow_listed_extension_only, bool):
            raise ValueError("Invalid type {0} for attribute 'allowListedExtensionsOnly' in policy. Expected bool"
                             .format(type(allow_listed_extension_only).__name__))

        extension_allowlist = self.extension_policy.get("extensions", {})

        # CRP allows extension names to be any case. We use a case-folded dict to do a case-insensitive query of the allowlist.
        should_allow = not allow_listed_extension_only or extension_allowlist.get(self.extension_to_check.name.lower()) is not None
        return should_allow

    def should_enforce_signature(self):
        """
        Return whether we should enforce signature based on policy.

        If policy feature not enabled, return False.
        Individual policy takes precedence over global - if individual signing policy present, return true/false based on
        individual policy. Else, return true/false based on global policy.
        """
        if not self.is_policy_enforcement_enabled():
            return False

        extension_dict = self.extension_policy.get("extensions", {})
        global_signature_required = self.extension_policy.get("signatureRequired", DEFAULT_SIGNATURE_REQUIRED)
        if not isinstance(global_signature_required, bool):
            raise ValueError("Invalid type {0} for attribute 'signatureRequired' in policy. Expected bool"
                             .format(type(global_signature_required).__name__))
        extension_individual_policy = extension_dict.get(self.extension_to_check.name.lower())
        if extension_individual_policy is None:
            return global_signature_required
        else:
            individual_signature_required = extension_individual_policy.get("signatureRequired")
            # Currently, CaseFoldedDict.get() does not support a default return value, so we explicitly set the default.
            if individual_signature_required is None:
                individual_signature_required = DEFAULT_SIGNATURE_REQUIRED
            if not isinstance(individual_signature_required, bool):
                raise ValueError("Invalid type {0} for attribute 'signatureRequired' in policy. Expected bool"
                                 .format(type(individual_signature_required).__name__))
            return individual_signature_required
        

