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

from azurelinuxagent.common import logger
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils.distro_version import DistroVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import PolicyError
from azurelinuxagent.common.osutil import get_osutil
import azurelinuxagent.ga.policy.regorus as regorus

# Define support matrix for Regorus and policy engine feature.
# Dict in the format: { distro:min_supported_version }
POLICY_SUPPORTED_DISTROS_MIN_VERSIONS = {
    'ubuntu': DistroVersion('16.04'),
    'mariner': DistroVersion('2'),
    'azurelinux': DistroVersion('3')
}
# TODO: add 'arm64', 'aarch64' here once support is enabled for ARM64
POLICY_SUPPORTED_ARCHITECTURE = ['x86_64']


class PolicyEngine(object):
    """
    Implements policy engine API. Class will always be initialized, but if the Regorus import fails,
    all methods will be no-ops.

    If any errors are thrown in regorus.py, they will be caught and handled here. add_policy, add_data,
    and set_input will be no-ops, eval_query will return an empty dict
    """
    def __init__(self, rule_file, policy_file):
        """
        rule_file: Path to a Rego file that specifies rules for policy behavior.

        policy_file: Path to a JSON file that specifies parameters for policy behavior - for example,
        whether allowlist or extension signing should be enforced.
        The expected file format is:
        {
            "azureGuestAgentPolicy": {
                "policyVersion": "0.1.0",
                "signingRules": {
                    "extensionSigned": <true, false>
                },
                "allowListOnly": <true, false>
            },
            "azureGuestExtensionsPolicy": {
                "allowed_ext_1": {
                    "signingRules": {
                        "extensionSigned": <true, false>
                    }
                }
        }
        """
        self._policy_engine_enabled = False
        self._engine = None
        if not self.is_policy_enforcement_enabled():
            self.log_policy(msg="Policy enforcement is not enabled.")
            return  # policy_engine_enabled is not set to True

        if not self.is_policy_enforcement_supported():
            # TODO: Update this error message when conf flag is removed post private preview.
            msg = "Attempted to enable policy enforcement, but feature is not supported on this platform."
            self.log_policy(msg=msg)
            raise PolicyError(msg)

        try:
            self._engine = regorus.Engine()
            self._engine.add_policy(rule_file)
            self._engine.add_data(policy_file)
            self._policy_engine_enabled = True
        except Exception as ex:
            msg = "Failed to initialize Regorus policy engine: '{0}'".format(ex)
            self.log_policy(msg=msg)
            raise PolicyError(msg)

    @classmethod
    def log_policy(cls, msg, is_success=True, op=WALAEventOperation.Policy, send_event=True):
        """
        Log information to console and telemetry.
        """
        if is_success:
            logger.info("[Policy] " + msg)
        else:
            logger.error("[Policy] " + msg)
        if send_event:
            add_event(op=op, message=msg, is_success=is_success)

    @staticmethod
    def is_policy_enforcement_enabled():
        """Check whether user has opted into policy enforcement feature"""
        # TODO: Remove conf flag post private preview and add other checks here.
        return conf.get_extension_policy_enabled()

    @staticmethod
    def is_policy_enforcement_supported():
        """Check that both platform architecture and distro/version are supported."""
        osutil = get_osutil()
        arch = osutil.get_vm_arch()
        if arch not in POLICY_SUPPORTED_ARCHITECTURE:
            return False
        __distro__ = get_distro()
        DISTRO_NAME = __distro__[0]
        DISTRO_VERSION = __distro__[1]
        try:
            distro_version = DistroVersion(DISTRO_VERSION)
        except ValueError:
            raise ValueError

        # Check if the distro is in the support matrix and if the version is supported
        if DISTRO_NAME in POLICY_SUPPORTED_DISTROS_MIN_VERSIONS:
            min_version = POLICY_SUPPORTED_DISTROS_MIN_VERSIONS[DISTRO_NAME]
            return distro_version >= min_version
        else:
            return False

    @property
    def policy_engine_enabled(self):
        """This property tracks whether the feature is enabled and Regorus engine has been successfully initialized"""
        return self._policy_engine_enabled

    def evaluate_query(self, input_json, query):
        """
        Expected format for input_json:
        {
            "extensions": {
                "<extension_name_1>": {
                    "signingInfo": {
                        "extensionSigned": <true, false>
                    }
                }, ...
        }

        Expected format for query: "data.agent_extension_policy.extensions_to_download"
        """
        # This method should never be called if policy is not enabled, this would be a developer error.
        if not self.policy_engine_enabled:
            raise PolicyError("Policy enforcement is disabled, cannot evaluate query.")

        try:
            self._engine.set_input(input_json)
            full_result = self._engine.eval_query(query)
            value = full_result['result'][0]['expressions'][0]['value']
            return value
        except Exception as ex:
            msg = "Failed to evaluate query for Regorus policy engine: '{0}'".format(ex)
            self.log_policy(msg=msg, is_success=False)
            raise PolicyError(msg)


# TODO: Implement class ExtensionPolicyEngine with API is_extension_download_allowed(ext_name) that calls evaluate_query.
