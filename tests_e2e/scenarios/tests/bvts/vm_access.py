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
# BVT for the VmAccess extension
#
# The test executes VmAccess to add a user and then verifies that an SSH connection to the VM can
# be established with that user's identity.
#
import uuid

from assertpy import assert_that
from pathlib import Path

from tests_e2e.scenarios.lib.agent_test import AgentTest
from tests_e2e.scenarios.lib.identifiers import VmExtensionIds
from tests_e2e.scenarios.lib.logging import log
from tests_e2e.scenarios.lib.shell import run_command
from tests_e2e.scenarios.lib.ssh_client import SshClient

from tests_e2e.scenarios.lib.vm_extension import VmExtension


class VmAccessBvt(AgentTest):
    def run(self):
        # Try to use a unique username for each test run (note that we truncate to 32 chars to
        # comply with the rules for usernames)
        log.info("Generating a new username and SSH key")
        username: str = f"test-{uuid.uuid4()}"[0:32]
        log.info("Username: %s", username)

        # Create an SSH key for the user and fetch the public key
        private_key_file: Path = self._context.working_directory/f"{username}_rsa"
        public_key_file: Path = self._context.working_directory/f"{username}_rsa.pub"
        log.info("Generating SSH key as %s", private_key_file)
        run_command(["ssh-keygen", "-m", "PEM", "-t", "rsa", "-b", "4096", "-q", "-N", "", "-f", str(private_key_file)])
        with public_key_file.open() as f:
            public_key = f.read()

        # Invoke the extension
        vm_access = VmExtension(self._context.vm, VmExtensionIds.VmAccess, resource_name="VmAccess")
        vm_access.enable(
            protected_settings={
                'username': username,
                'ssh_key': public_key,
                'reset_ssh': 'false'
            }
        )
        vm_access.assert_instance_view()

        # Verify the user was added correctly by starting an SSH session to the VM
        log.info("Verifying SSH connection to the test VM")
        ssh = SshClient(ip_address=self._context.vm_ip_address, username=username, private_key_file=private_key_file)
        stdout = ssh.run_command("echo $(hostname):$USER")
        assert_that(stdout.rstrip()).described_as("Output from SSH command").is_equal_to(f"{self._context.vm.name}:{username}")
        log.info("SSH command output: %s", stdout)


if __name__ == "__main__":
    VmAccessBvt.run_from_command_line()
