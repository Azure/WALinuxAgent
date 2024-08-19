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
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
import platform

# Define support matrix for Regorus and policy engine feature.
# Dict in the format: { distro:min_supported_version }
POLICY_SUPPORTED_DISTROS = {
    'ubuntu': FlexibleVersion('16.04'),
    'mariner': FlexibleVersion('2')
}
POLICY_SUPPORTED_ARCHITECTURE = ['x86_64', 'amd64']


# Common logging function across PolicyEngineConfigurator and PolicyEngine classes,
# so should be a module-level function.
def log_policy(formatted_string, is_success=True, op=WALAEventOperation.Policy, send_event=True):
    """
    Log information to console and telemetry.
    """
    if is_success:
        logger.info("[Policy] " + formatted_string)
    else:
        logger.error("[Policy] " + formatted_string)
    if send_event:
        add_event(op=op, message=formatted_string, is_success=is_success)


class PolicyEngineConfigurator:
    """
    This Singleton class is responsible for checking if policy is enabled for the agent.
    Policy can only be enabled/disabled via configuration file, and can only be enabled on supported distros.
    If an error occurs during Regorus import, policy will be globally disabled for the agent via the _policy_enabled flag.
    Use: PolicyEngineConfigurator.get_instance()
    """
    _instance = None  # configurator is implemented as a singleton
    _initialized = False  # set to true on first init, even if Regorus import fails, we don't want to retry.
    _policy_enabled = False

    def __init__(self):
        # we only attempt to import Regorus if it is both enabled via conf and supported by the platform
        try:
            if PolicyEngineConfigurator._initialized:
                return

            if not self.is_policy_configured():
                log_policy("Policy enforcement is disabled.")
                return

            if not self._is_policy_supported():
                # If distro is unsupported but feature is enabled, we never set _policy_enabled=True.
                # Any methods will be no-ops, and query evaluation will return an empty allowlist
                # so no extensions will be allowed.
                log_policy("Policy enforcement is unsupported on this platform.")
                return

            # Regorus import should only be attempted after completing the above checks within
            # the configurator, but the module itself needs to be accessible outside this class.
            global regorus  # pylint: disable=global-statement
            import azurelinuxagent.ga.policy.regorus as regorus
            PolicyEngineConfigurator._policy_enabled = True

        except (ImportError, NameError) as ex:
            log_policy("Error: Failed to import Regorus module and initialize policy engine. {0}".format(ex), is_success=False)
        except Exception as ex:
            log_policy("Error: Failed to enable policy enforcement. '{0}'".format(ex), is_success=False)
        finally:
            PolicyEngineConfigurator._initialized = True

    @staticmethod
    def is_policy_configured():
        """Return True if the policy enforcement feature is configured/enabled by customer."""
        # TODO: call from ExtensionPolicyEngine to bypass policy checking
        #  Remove conf flag post private preview and add other checks here.
        return conf.get_extension_policy_enabled()

    @staticmethod
    def _is_policy_supported():
        """Return True if the platform/distro supports policy enforcement."""
        arch = platform.machine().lower()
        if arch not in POLICY_SUPPORTED_ARCHITECTURE:
            return False
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            raise ValueError

        # Check if the distro is in the support matrix and if the version is supported
        if distro_name in POLICY_SUPPORTED_DISTROS:
            min_version = POLICY_SUPPORTED_DISTROS[distro_name]
            return distro_version >= min_version
        else:
            return False

    @staticmethod
    def get_instance():
        if PolicyEngineConfigurator._instance is None:
            PolicyEngineConfigurator._instance = PolicyEngineConfigurator()
        return PolicyEngineConfigurator._instance

    @staticmethod
    def get_policy_enabled():
        return PolicyEngineConfigurator.get_instance()._policy_enabled


class PolicyEngine(object):
    """
    Implements policy engine API. Class will always be initialized, but if the Regorus import fails,
    all methods will be no-ops.

    If any errors are thrown in regorus.py, they will be caught and handled here. add_policy, add_data,
    and set_input will be no-ops, eval_query will return an empty dict
    """
    def __init__(self):
        self._policy_engine_enabled = False
        self._engine = None
        try:
            if PolicyEngineConfigurator.get_instance().get_policy_enabled():
                self._engine = regorus.Engine()  # regorus will have already been imported in configurator
                self._policy_engine_enabled = True
        except (ImportError, NameError) as ex:
            log_policy("Error: Failed to initialize Regorus policy engine due to import failure. {0}".format(ex), is_success=False)
        except Exception as ex:
            log_policy("Error: Failed to initialize Regorus policy engine. '{0}'".format(ex), is_success=False)

    @property
    def policy_engine_enabled(self):
        return self._policy_engine_enabled

    def add_policy(self, policy_file):
        """Policy_path should be a path to a valid Rego policy rule file."""
        if not self.policy_engine_enabled:
            return

        try:
            self._engine.add_policy(policy_file)
        except Exception as ex:
            log_policy("Error: Failed to add policy to Regorus policy engine. '{0}'".format(ex), is_success=False)

    def add_data(self, data_file):
        """Data_file should be a path to a valid JSON data file."""
        if not self.policy_engine_enabled:
            return

        try:
            self._engine.add_data(data_file)
        except Exception as ex:
            log_policy("Error: Failed to add data to Regorus policy engine. '{0}'".format(ex), is_success=False)

    def set_input(self, input_json):
        """Input_json should be a JSON object."""
        if not self.policy_engine_enabled:
            return

        try:
            self._engine.set_input(input_json)
        except Exception as ex:
            log_policy("Error: Failed to set input for Regorus policy engine. '{0}'".format(ex), is_success=False)

    def evaluate_query(self, query):
        if not self.policy_engine_enabled:
            return {}

        try:
            full_result = self._engine.eval_query(query)
            value = full_result['result'][0]['expressions'][0]['value']
            return value
        except Exception as ex:
            log_policy("Error: Failed to evaluate query for Regorus policy engine. '{0}'".format(ex), is_success=False)
            return {}

# TODO: ADO task 29144116
# Implement code (ExtensionPolicyEngine) to return allowed list and handle/surface errors
