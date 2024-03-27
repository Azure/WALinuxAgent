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

from tests_e2e.tests.lib.agent_test import AgentVmssTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class VmssTest(AgentVmssTest):
    """
    Sample test for scale sets
    """
    def run(self):
        for address in self._context.vmss.get_instances_ip_address():
            ssh_client: SshClient = SshClient(ip_address=address.ip_address, username=self._context.username, identity_file=self._context.identity_file)
            log.info("%s: Hostname: %s", address.instance_name, ssh_client.run_command("hostname").strip())
        log.info("* PASSED *")


if __name__ == "__main__":
    VmssTest.run_from_command_line()
