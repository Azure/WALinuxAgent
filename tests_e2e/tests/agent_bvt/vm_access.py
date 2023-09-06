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

from tests_e2e.tests.lib.agent_test import AgentTest, TestSkipped
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient

from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class VmAccessBvt(AgentTest):
    def run(self):
        ssh: SshClient = self._context.create_ssh_client()
        if not VmExtensionIds.VmAccess.supports_distro(ssh.run_command("uname -a")):
            raise TestSkipped("Currently VMAccess is not supported on this distro")

        # Try to use a unique username for each test run (note that we truncate to 32 chars to
        # comply with the rules for usernames)
        log.info("Generating a new username and SSH key")
        username: str = f"test-{uuid.uuid4()}"[0:32]
        log.info("Username: %s", username)

        # Create an SSH key for the user and fetch the public key
        private_key_file: Path = self._context.working_directory/f"{username}_rsa"
        public_key_file: Path = self._context.working_directory/f"{username}_rsa.pub"
        log.info("Generating SSH key as %s", private_key_file)
        ssh = SshClient(ip_address=self._context.vm_ip_address, username=username, private_key_file=private_key_file)
        ssh.generate_ssh_key(private_key_file)
        with public_key_file.open() as f:
            public_key = f.read()

        # Invoke the extension
        vm_access = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.VmAccess, resource_name="VmAccess")
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
        stdout = ssh.run_command("echo -n $USER")
        assert_that(stdout).described_as("Output from SSH command").is_equal_to(username)
        log.info("SSH command output ($USER): %s", stdout)


if __name__ == "__main__":
    VmAccessBvt.run_from_command_line()
