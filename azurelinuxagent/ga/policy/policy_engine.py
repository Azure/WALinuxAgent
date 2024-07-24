# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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

from azurelinuxagent.common import logger
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf


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

            if not conf.get_extension_policy_enabled():
                log_policy("Policy enforcement is disabled via configuration file.")
                return

            if not self._is_policy_supported():
                log_policy("Policy enforcement is unsupported on this platform.")
                return

            global regorus
            import regorus
            PolicyEngineConfigurator._policy_enabled = True

        except (ImportError, NameError) as ex:
            log_policy("Error: Failed to import Regorus module and initialize policy engine.", is_success=False)
            raise ex
        except Exception as ex:
            log_policy("Error: Failed to enable policy enforcement. '{0}'".format(ex), is_success=False)
            raise ex
        finally:
            PolicyEngineConfigurator._initialized = True

    @staticmethod
    def _is_policy_supported():
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            return False
        return distro_name.lower() == 'ubuntu' and distro_version.major >= 16

    @staticmethod
    def get_instance():
        if PolicyEngineConfigurator._instance is None:
            PolicyEngineConfigurator._instance = PolicyEngineConfigurator()
        return PolicyEngineConfigurator._instance

    @staticmethod
    def get_policy_enabled():
        return PolicyEngineConfigurator._policy_enabled


class PolicyEngine:
    """
    Implements policy engine API. Class will always be initialized, but if the Regorus import fails,
    all methods will be no-ops.
    """
    def __init__(self):
        self._policy_engine_enabled = False
        self._engine = None
        try:
            if PolicyEngineConfigurator.get_instance().get_policy_enabled():
                self._engine = regorus.Engine()  # regorus will have already been imported in configurator
                self._policy_engine_enabled = True
        except (ImportError, NameError):
            log_policy("Error: Failed to initialize Regorus policy engine due to import failure.", is_success=False)
            raise NameError
        except Exception as ex:
            log_policy("Error: Failed to initialize Regorus policy engine. '{0}'".format(ex), is_success=False)
            raise ex

    @property
    def policy_engine_enabled(self):
        return self._policy_engine_enabled


class ExtensionPolicyEngine(PolicyEngine):
    """
    Implements all extension policy-related operations.
    """
    def __init__(self):
        self._extension_policy_engine_enabled = False
        super().__init__()
        # if Regorus engine initialization fails, we shouldn't try to load any files.
        if self.policy_engine_enabled:
            try:
                # TO DO: load policy and data file here
                self._extension_policy_enabled = True
                log_policy("Successfully enabled extension policy enforcement.",
                           op=WALAEventOperation.ExtensionPolicy)
            except Exception as ex:
                log_policy("Error: Failed to enable extension policy enforcement. '{0}'".format(ex), is_success=False,
                           op=WALAEventOperation.ExtensionPolicy)

    @property
    def extension_policy_engine_enabled(self):
        return self._extension_policy_engine_enabled
