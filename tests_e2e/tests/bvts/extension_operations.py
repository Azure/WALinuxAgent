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
# BVT for extension operations (Install/Enable/Update/Uninstall).
#
# The test executes an older version of an extension, then updates it to a newer version, and lastly
# it removes it. The actual extension is irrelevant, but the test uses CustomScript for simplicity,
# since it's invocation is trivial and the entire extension workflow  can be tested end-to-end by
# checking the message in the status produced by the extension.
#
import uuid

from assertpy import assert_that

from azure.core.exceptions import ResourceNotFoundError

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtensionOperationsBvt(AgentTest):
    def run(self):
        ssh_client: SshClient = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

        is_arm64: bool = ssh_client.get_architecture() == "aarch64"

        custom_script_2_0 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript,
            resource_name="CustomScript")

        if is_arm64:
            log.info("Will skip the update scenario, since currently there is only 1 version of CSE on ARM64")
        else:
            log.info("Installing %s", custom_script_2_0)
            message = f"Hello {uuid.uuid4()}!"
            custom_script_2_0.enable(
                settings={
                    'commandToExecute': f"echo \'{message}\'"
                },
                auto_upgrade_minor_version=False
            )
            custom_script_2_0.assert_instance_view(expected_version="2.0", expected_message=message)

        custom_script_2_1 = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"),
            resource_name="CustomScript")

        if is_arm64:
            log.info("Installing %s", custom_script_2_1)
        else:
            log.info("Updating %s", custom_script_2_0)

        message = f"Hello {uuid.uuid4()}!"
        custom_script_2_1.enable(
            settings={
                'commandToExecute': f"echo \'{message}\'"
            }
        )
        custom_script_2_1.assert_instance_view(expected_version="2.1", expected_message=message)

        custom_script_2_1.delete()

        assert_that(custom_script_2_1.get_instance_view).\
            described_as("Fetching the instance view should fail after removing the extension").\
            raises(ResourceNotFoundError)


if __name__ == "__main__":
    ExtensionOperationsBvt.run_from_command_line()
