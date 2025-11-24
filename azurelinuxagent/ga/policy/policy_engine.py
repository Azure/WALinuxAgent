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
import re
import os
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo


# Default policy values to be used when customer does not specify these attributes in the policy file.
_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
_DEFAULT_SIGNATURE_REQUIRED = False
_DEFAULT_EXTENSIONS = {}

# Agent supports up to this version of the policy file ("policyVersion" in schema).
# Increment this number when any new attributes are added to the policy schema.
_MAX_SUPPORTED_POLICY_VERSION = "0.1.0"

# Extension signature validation is currently only supported on CVMs. If a non-CVM user creates a policy with signature
# required, we should raise an error indicating that the policy is invalid.
# TODO: Remove once signature validation is supported on all VMs
_CVM_ONLY_POLICIES = ["signatureRequired"]


class PolicyError(AgentError):
    """
    Base class for policy-related errors.
    """
    def __init__(self, msg=None, inner=None):
        super(PolicyError, self).__init__(msg, inner)


class InvalidPolicyError(PolicyError):
    """
    Error raised if user-provided policy is invalid.
    """
    def __init__(self, msg, inner=None):
        msg = "Customer-provided policy file ('{0}') is invalid, please correct the following error: {1}".format(conf.get_policy_file_path(), msg)
        super(InvalidPolicyError, self).__init__(msg, inner)


class ExtensionSignaturePolicyError(PolicyError):
    """
    Error raised when policy requires signature, but extension is not signed and was not previously validated.
    This error does not accept a message.
    """
    def __init__(self):
        super(ExtensionSignaturePolicyError, self).__init__()


class ExtensionDisallowedError(PolicyError):
    """
    Error raised when extension is not present in the policy allowlist.
    This error does not accept a message.
    """
    def __init__(self):
        super(ExtensionDisallowedError, self).__init__()


class _PolicyEngine(object):
    """
    Implements base policy engine API.

    Note: All public methods in PolicyEngine classes must verify that policy enforcement is enabled and act as no-ops when it is not.
    """
    def __init__(self):
        """
        Initialize policy engine with a default policy. This should not fail or raise any errors.
        """
        self._policy_enforcement_enabled = _PolicyEngine.__get_policy_enforcement_enabled()
        default_policy = {
            "policyVersion": ustr(_MAX_SUPPORTED_POLICY_VERSION),
            "extensionPolicies": {
                "allowListedExtensionsOnly": _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY,
                "signatureRequired": _DEFAULT_SIGNATURE_REQUIRED,
                "extensions": _DEFAULT_EXTENSIONS
            }
        }
        self._policy = default_policy

    @property
    def policy_enforcement_enabled(self):
        return self._policy_enforcement_enabled

    def update_policy(self, goal_state_history):
        """
        If policy enforcement is enabled, read and parse policy file, and update the policy being enforced.

        :param goal_state_history: GoalStateHistory object. Policy file contents are saved to the history folder.
        """
        # Check and update if policy enforcement is enabled each time policy is updated
        self._policy_enforcement_enabled = _PolicyEngine.__get_policy_enforcement_enabled()
        if not self._policy_enforcement_enabled:
            return

        _PolicyEngine._log_policy_event("Policy enforcement is enabled.")
        policy_file_contents = self.__read_policy(goal_state_history)
        self._policy = self._parse_policy(policy_file_contents)

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
    def __get_policy_enforcement_enabled():
        """
        Return True if policy enforcement is enabled. Policy is enabled if:
            1. policy file exists at the expected location
            2. the conf flag "Debug.EnableExtensionPolicy" is set to True.

        TODO: this behavior is temporary for telemetry release only. After telemetry release, remove
        the check for the policy file, and always enforce policy if the conf flag is True. 

        This method runs during policy engine initialization and should not raise errors.

        """
        return conf.get_extension_policy_enabled() and os.path.isfile(conf.get_policy_file_path())


    @staticmethod
    def __read_policy(goal_state_history):
        """
        Read customer-provided policy JSON file, load and return as a dict. Policy file contents are saved to the goal state history folder.

        Policy file is expected to be at conf.get_policy_file_path(). Note that this method should only be called
        after verifying that the file exists (currently done in __init__).

        Raise InvalidPolicyError if JSON is invalid, or any exceptions are thrown while reading the file.
        """
        policy_file_contents = None
        try:
            with open(conf.get_policy_file_path(), 'r') as f:
                policy_file_contents = f.read()

                # Save policy file contents to goal state history folder
                try:
                    goal_state_history.save(policy_file_contents, "waagent_policy.json")
                except Exception as ex:
                    logger.warn("Failed to save policy to history, continuing with goal state processing. Error: {0}", ustr(ex))

                _PolicyEngine._log_policy_event(
                    "Enforcing policy using policy file found at '{0}'.".format(conf.get_policy_file_path()))

                # json.loads will raise error if file contents are not a valid json (including empty file).
                custom_policy = json.loads(policy_file_contents)

        except ValueError as ex:
            msg = "policy file does not conform to valid json syntax."
            if policy_file_contents is not None:
                msg += " File contents: {0}".format(policy_file_contents)
            raise InvalidPolicyError(msg=msg, inner=ex)
        except Exception as ex:
            msg = "unable to read or load policy file."
            if policy_file_contents is not None:
                msg += " File contents: {0}".format(policy_file_contents)
            raise InvalidPolicyError(msg=msg, inner=ex)

        return custom_policy

    @staticmethod
    def _parse_policy(policy):
        """
        Parses the given policy document and returns an equivalent document that has been populated with default values and verified for correctness, i.e.
        that conforms the following schema:

            {
                 "policyVersion": "0.1.0",
                 "extensionPolicies": {
                     "allowListedExtensionsOnly": <true, false>, [Optional; default: false]
                     "signatureRequired": <true, false>, [Optional; default: false]
                     "extensions": { [Optional; default: {} (empty)]
                         "<extension_name>": {
                             "signatureRequired": <true, false> [Optional; no default]
                             "runtimePolicy": <extension-specific policy> [Optional; no default]
                         }
                     },
                 }
             }

        Raises InvalidPolicyError if the policy document is invalid.
        """
        if not isinstance(policy, dict):
            raise InvalidPolicyError("expected an object describing a Policy; got {0}.".format(type(policy).__name__))

        _PolicyEngine._check_attributes(policy, object_name="policy", valid_attributes=["policyVersion", "extensionPolicies"])

        return {
            "policyVersion": _PolicyEngine._parse_policy_version(policy),
            "extensionPolicies": _PolicyEngine._parse_extension_policies(policy)
        }

    @staticmethod
    def _parse_policy_version(policy):
        """
        Validate and return "policyVersion" attribute. If not a string in the format "major[.minor[.patch]]", raise InvalidPolicyError.
        If policy_version is greater than maximum supported version, raise InvalidPolicyError.
        """
        version = _PolicyEngine._get_string(policy, attribute="policyVersion")

        if not re.match(r"^\d+(\.\d+(\.\d+)?)?$", version):
            raise InvalidPolicyError("invalid value for attribute 'policyVersion': '{0}'; it should be in format 'major[.minor[.patch]]' (e.g., '1', '1.0', '1.0.0')".format(version))

        if FlexibleVersion(_MAX_SUPPORTED_POLICY_VERSION) < FlexibleVersion(version):
            raise InvalidPolicyError("policy version '{0}' is not supported. The agent supports policy versions up to '{1}'.".format(version, _MAX_SUPPORTED_POLICY_VERSION))

        return version

    @staticmethod
    def _parse_extension_policies(policy):
        """
        Parses the "extensionPolicies" attribute of the policy document. See _parse_policy() for schema.
        """
        extension_policies = _PolicyEngine._get_dictionary(policy, attribute="extensionPolicies", optional=True, default={})

        _PolicyEngine._check_attributes(extension_policies, object_name="extensionPolicies", valid_attributes=["allowListedExtensionsOnly", "signatureRequired", "extensions"])

        return {
            "allowListedExtensionsOnly": _PolicyEngine._get_boolean(extension_policies, attribute="allowListedExtensionsOnly", name_prefix="extensionPolicies.", optional=True, default=_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY),
            "signatureRequired": _PolicyEngine._get_boolean(extension_policies, attribute="signatureRequired", name_prefix="extensionPolicies.", optional=True, default=_DEFAULT_SIGNATURE_REQUIRED),
            "extensions": _PolicyEngine._parse_extensions(
                _PolicyEngine._get_dictionary(extension_policies, attribute="extensions", name_prefix="extensionPolicies.", optional=True, default=_DEFAULT_EXTENSIONS)
            )
        }

    @staticmethod
    def _parse_extensions(extensions):
        """
        Parses the "extensions" attribute. See _parse_policy() for schema.
        The return value is a case-folded dict. CRP allows extensions to be any case, so we allow for case-insensitive lookup of individual extension policies.
        """
        parsed = _CaseFoldedDict.from_dict({})

        for extension, extension_policy in extensions.items():
            if not isinstance(extension_policy, dict):
                raise InvalidPolicyError("invalid type {0} for attribute 'extensionPolicies.extensions.{1}'; must be 'object'".format(type(extension_policy).__name__, extension))
            parsed[extension] = _PolicyEngine._parse_extension(extension_policy)

        return parsed

    @staticmethod
    def _parse_extension(extension):
        """
        Parses an individual extension. See _parse_policy() for schema.
        """
        extension_attribute_name = "extensionPolicies.extensions.{0}".format(extension)

        _PolicyEngine._check_attributes(extension, object_name=extension_attribute_name, valid_attributes=["signatureRequired", "runtimePolicy"])

        return_value = {}

        signature_required = _PolicyEngine._get_boolean(extension, attribute="signatureRequired", name_prefix=extension_attribute_name, optional=True, default=None)
        if signature_required is not None:
            return_value["signatureRequired"] = signature_required

        # The runtimePolicy is an arbitrary object.
        runtime_policy = extension.get("runtimePolicy")
        if runtime_policy is not None:
            return_value["runtimePolicy"] = runtime_policy

        return return_value

    @staticmethod
    def _check_attributes(object_, object_name, valid_attributes):
        """
        Check that the given object, which should be a dictionary, has only the specified attributes.
        If any other attributes are present, raise InvalidPolicyError.
        The object_name is used in the error message.
        """
        for k in object_.keys():
            if k not in valid_attributes:
                raise InvalidPolicyError("unrecognized attribute '{0}' in {1}".format(k, object_name))

            if not ConfidentialVMInfo.is_confidential_vm() and k in _CVM_ONLY_POLICIES:
                raise InvalidPolicyError("attribute '{0}' is only supported on confidential virtual machines (CVMs).".format(k))

    @staticmethod
    def _get_dictionary(object_, attribute, name_prefix="", optional=False, default=None):
        """
        Returns object[attribute] if it exists, verifying that it is a dictionary.
        If object_[attribute] does not exist and 'optional' is True, returns 'default'; if 'optional' is False raises InvalidPolicyError.
        If object_[attribute] is not a dictionary, raises InvalidPolicyError.
        The name_prefix indicates the path of the attribute within the policy document and is used in the error message.
        """
        return _PolicyEngine._get_value(object_, attribute, name_prefix, dict, "object", optional=optional, default=default)

    @staticmethod
    def _get_string(object_, attribute, name_prefix="", optional=False, default=None):
        """
        Returns object[attribute] if it exists, verifying that it is a string, else returns default.
        If object_[attribute] does not exist and 'optional' is True, returns 'default'; if 'optional' is False raises InvalidPolicyError.
        If object_[attribute] is not a string, raises InvalidPolicyError.
        The name_prefix indicates the path of the attribute within the policy document and is used in the error message.
        """
        return _PolicyEngine._get_value(object_, attribute, name_prefix, ustr, "string", optional=optional, default=default)

    @staticmethod
    def _get_boolean(object_, attribute, name_prefix="", optional=False, default=None):
        """
        Returns object[attribute] if it exists, verifying that it is a boolean, else returns default.
        If object_[attribute] does not exist and 'optional' is True, returns 'default'; if 'optional' is False raises InvalidPolicyError.
        If object_[attribute] is not a boolean, raises InvalidPolicyError.
        The name_prefix indicates the path of the attribute within the policy document and is used in the error message.
        """
        return _PolicyEngine._get_value(object_, attribute, name_prefix, bool, "boolean", optional=optional, default=default)

    @staticmethod
    def _get_value(object_, attribute, name_prefix, type_, type_name, optional, default):
        """
        Returns object[attribute] if it exists, verifying that it is of the given type_, else returns default.
        If object_[attribute] does not exist and 'optional' is True, returns 'default'; if 'optional' is False raises InvalidPolicyError.
        If the type of object_[attribute] is not 'type_', raises InvalidPolicyError.
        The name_prefix indicates the path of the attribute within the policy document, the type_name indicates a user-friendly name for type_; both are used in the error message.
        """
        if default is not None and not optional:
            raise ValueError("default value should only be provided for optional attributes")
        value = object_.get(attribute)
        if value is None:
            if not optional:
                raise InvalidPolicyError("missing required attribute '{0}{1}'".format(name_prefix, attribute))
            return default
        if not isinstance(value, type_):
            raise InvalidPolicyError("invalid type {0} for attribute '{1}{2}'; must be '{3}'".format(type(value).__name__, name_prefix, attribute, type_name))
        return value


class ExtensionPolicyEngine(_PolicyEngine):

    def _should_allow_extension(self, extension_name):
        """
        Return whether we should allow extension download based on policy.
        If policy feature not enabled, return True.
        If allowListedExtensionsOnly=true, return true only if extension present in "extensions" allowlist.
        If allowListedExtensions=false, return true always.
        """
        if not self._policy_enforcement_enabled:
            return True

        allow_listed_extension_only = self._policy.get("extensionPolicies").get("allowListedExtensionsOnly")
        extension_allowlist = self._policy.get("extensionPolicies").get("extensions")

        should_allow = not allow_listed_extension_only or extension_allowlist.get(extension_name) is not None
        return should_allow

    def should_enforce_signature_validation(self, extension_name):
        """
        Return whether we should enforce signature based on policy.
        If policy feature not enabled, return False.
        Individual policy takes precedence over global.
        """
        if not self._policy_enforcement_enabled:
            return False

        global_signature_required = self._policy.get("extensionPolicies").get("signatureRequired")
        individual_policy = self._policy.get("extensionPolicies").get("extensions").get(extension_name)
        individual_signature_required = individual_policy.get("signatureRequired") if individual_policy is not None else None

        return individual_signature_required if individual_signature_required is not None else global_signature_required

    def check_extension_policy(self, extension_name, extension_is_signed):
        """
        Enforce all applicable extension policies.
        :param extension_name: extension name (string).
        :param extension_is_signed: Boolean indicating whether the extension is signed (or signature was previously validated, if extension is not being installed).
        :raises ExtensionDisallowedError: If the extension is not allowed by policy.
        :raises ExtensionSignaturePolicyError: If the extension is required to be signed but is not.
        """
        if not self._policy_enforcement_enabled:
            return

        extension_allowed = self._should_allow_extension(extension_name)
        if not extension_allowed:
            raise ExtensionDisallowedError()      # Caller sets message and error code, based on requested extension operation

        # TODO: Differentiate error handling:
        #   (1) New installation: extension is unsigned -> raise ExtensionUnsignedError
        #   (2) Existing installation: signature was never validated -> raise ExtensionSignatureNotValidatedError
        # Currently both cases raise the same error. They should use distinct exceptions/messages.
        enforce_signature = self.should_enforce_signature_validation(extension_name)
        if enforce_signature and not extension_is_signed:
            raise ExtensionSignaturePolicyError() # Caller sets message and error code, based on requested extension operation
