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

from azurelinuxagent.common import logger

# TO DO - remove path.append once the binary has been published to GA package
import sys
import os
regorus_dir = "/lib/tests_e2e/tests/executables"
sys.path.append(regorus_dir)
logger.info("Sys path:")
logger.info(sys.path)
os.environ['LD_LIBRARY_PATH'] = f"{regorus_dir}:{os.environ.get('LD_LIBRARY_PATH', '')}"
try:
    import regorus
    logger.info("Successfully imported regorus")
except ImportError:
    logger.info("Failed to import regorus module.")


class PolicyEngine:
    """Base class for policy engine"""
    def __init__(self):
        self._engine = regorus.Engine()
