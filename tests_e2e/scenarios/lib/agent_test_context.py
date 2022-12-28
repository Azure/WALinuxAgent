# Microsoft Azure Linux Agent
#
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
import argparse
import os

from pathlib import Path

import tests_e2e
from tests_e2e.scenarios.lib.identifiers import VmIdentifier


class AgentTestContext:
    """
    Execution context for tests. Defines the test VM and working directories for the test.
    """
    def __init__(
        self,
        vm: VmIdentifier,
        # E1101: Instance of 'list' has no '_path' member (no-member)
        test_source_directory: Path = Path(tests_e2e.__path__._path[0]),  # pylint: disable=E1101
        working_directory: Path = Path().home()/"waagent-tmp",
        remote_working_directory: Path = Path('/home')/os.getenv("USER")
    ):
        self._vm: VmIdentifier = vm
        self._test_source_directory: Path = test_source_directory
        self._working_directory: Path = working_directory
        self._remote_working_directory: Path = remote_working_directory

    @property
    def vm(self) -> VmIdentifier:
        return self._vm

    @property
    def test_source_directory(self) -> Path:
        return self._test_source_directory

    @property
    def working_directory(self) -> Path:
        return self._working_directory

    @property
    def remote_working_directory(self) -> Path:
        return self._remote_working_directory

    @staticmethod
    def from_args():
        parser = argparse.ArgumentParser()
        parser.add_argument('--location', required=True)
        parser.add_argument('--subscription', required=True)
        parser.add_argument('--group', required=True)
        parser.add_argument('--vm', required=True)

        args = parser.parse_args()

        return AgentTestContext(VmIdentifier(location=args.location, subscription=args.subscription, resource_group=args.group, name=args.vm))
