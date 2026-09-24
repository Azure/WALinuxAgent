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
# The provisioning Agent and Just In Time Access can create user accounts. The underlying code has dependencies on the
# Python version installed on the VM; in particular, the crypt module, which is used by the Agent to hash passwords, was
# removed on Python 3.13. On Python >= 3.13, the Agent uses the passlib module instead.
#
# Our current test infrastructure cannot automate scenarios to exercise the Provisioning Agent, nor JIT. In lieu of
# end-to-end tests for those features, we use this test to exercise the code affected by those changes in Python.
#
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentCreateUser(AgentVmTest):
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        log.info("Creating test user...")
        test_user = ssh_client.run_command("create_test_user.py", use_sudo=True).rstrip()
        log.info(f"The test user was created successfully: {test_user}")

        # A simple check in case there is a bug in create_test_user.py
        log.info("Looking for test user in /etc/passwd...")
        result = ssh_client.run_command(f"grep {test_user} /etc/passwd").rstrip()
        log.info(f"Found test user: {result}")

        log.info("Removing test user...")
        ssh_client.run_command(f"create_test_user.py --delete {test_user}", use_sudo=True)
        log.info("The test user was removed successfully")


if __name__ == "__main__":
    AgentCreateUser.run_from_command_line()
