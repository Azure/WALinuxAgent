#!/usr/bin/env python3

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

#
# This test adds multiple instances of RCv2 and verifies that the extensions are processed and deleted as expected.
#

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


class MultiConfigExt(AgentTest):
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)


if __name__ == "__main__":
    MultiConfigExt.run_from_command_line()
