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

# This is a placeholder policy engine class to test that the regorus
# dependency is correctly installed.
# pylint: disable=too-few-public-methods

import pwd
import os
import sys

from azurelinuxagent.common import logger
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf

def log_policy_info(formatted_string, op=WALAEventOperation.Policy, send_event=True):
    """Log information to console and telemetry."""
    logger.info("[Policy] " + formatted_string)
    if send_event:
        add_event(op=op, message=formatted_string)


class PolicyEngine:
    """Base class for policy engine"""
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    @staticmethod
    def _is_policy_supported():
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            return False
        return distro_name.lower() == 'ubuntu' and distro_version.major >= 16

    def __init__(self):
        self._initialized = False
        self._policy_supported = False
        self._extension_policy_enabled = False
        self._engine = None

    def initialize(self):
        try:
            if self._initialized:
                return
            self._policy_supported = self._is_policy_supported()

            if not self._policy_supported:
                log_policy_info("Policy enforcement is not supported on {0}".format(get_distro()))
                return

            if not conf.get_extension_policy_enabled():
                log_policy_info("Extension policy enforcement is disabled")
                return

            # TO DO - import code is for e2e testing, remove once the binary has been published to GA package
            user = next((u.pw_name for u in pwd.getpwall() if u.pw_uid == 1000), None)
            regorus_dir = os.path.join(("/home/" + str(user)), "lib/tests_e2e/tests/executables")
            sys.path.append(regorus_dir)
            import regorus  # pylint: disable=import-outside-toplevel

            self._engine = regorus.Engine()
            self._extension_policy_enabled = True
        except Exception as exception:
            log_policy_info("Error initializing policy engine: {0}".format(exception))
        finally:
            log_policy_info("Policy enforcement enabled: {0}".format(self._extension_policy_enabled))
            self._initialized = True

    def disable(self):
        self._extension_policy_enabled = False

    def get_extension_policy_enabled(self):
        return self._extension_policy_enabled
