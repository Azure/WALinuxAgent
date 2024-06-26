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
# This test disables extension processing on waagent.conf and verifies that extensions are not processed, but the
# agent continues reporting status.
#

import uuid

from assertpy import assert_that, fail
from typing import Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtensionsPolicy(AgentVmTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient, settings: Any):
            self.extension = extension
            self.settings = settings
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Enable policy engine on the test VM
        log.info("")
        log.info("Enable extension policy enforcement on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)
        log.info("Enable policy completed:\n%s", output)

        # Prepare test cases
        # TO DO - add more extensions/cases after full policy functionality is implemented
        unique = str(uuid.uuid4())
        test_file = f"waagent-test.{unique}"
        test_cases = [
            ExtensionsPolicy.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript,
                                              resource_name="CustomScript"),
                {'commandToExecute': f"echo '{unique}' > /tmp/{test_file}"}
            )
        ]

        for t in test_cases:
            log.info("")
            log.info("Test case: %s", t.extension)

            # validate that policy engine is correctly initialized
            log.info("The agent should initialize the policy engine")
            try:
                t.extension.enable(settings=t.settings, force_update=True, timeout=6 * 60)
                log.info("Checking that policy engine is successfully initialized...")
                expected_msg = "Extension policy is enabled. Continuing with policy enforcement."
                ssh_client.run_command("grep \"{0}\" /var/log/waagent.log".format(expected_msg))
                log.info("Successfully initialized policy engine")
            except Exception as error:
                fail(f"Unexpected error while processing {t.extension.__str__()} during policy engine instantiation")

        log.info("Disable extension policy enforcement on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
        log.info("Disable policy completed:\n%s", output)

if __name__ == "__main__":
    ExtensionsPolicy.run_from_command_line()
