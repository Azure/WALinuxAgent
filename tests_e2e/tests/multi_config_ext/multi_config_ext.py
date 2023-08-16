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
import uuid
from typing import Dict, List

from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class MultiConfigExt(AgentTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient):
            self.extension = extension
            self.test_guid: str = str(uuid.uuid4())

    def enable_and_validate_test_cases(self, test_cases: List[TestCase]):
        for t in test_cases:
            log.info("")
            log.info("Adding {0} on the test VM", t.extension)
            t.extension.enable(settings={
                "source": {
                    "script": f"echo {t.test_guid}"
                }
            })
            t.extension.assert_instance_view()

    def assert_guids_in_instance_view(self, test_cases: List[TestCase]):
        for t in test_cases:
            log.info("")
            log.info("Checking status message for {0} on the test VM", t.extension)
            t.extension.assert_instance_view(expected_message=f"{t.test_guid}")

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)

        # Create 3 different RCv2 extensions and assign each a unique guid. We will use this guid to verify the
        # extension status later
        test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt1": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler, resource_name="MCExt1")
            ),
            "MCExt2": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler, resource_name="MCExt2")
            ),
            "MCExt3": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler, resource_name="MCExt3")
            )
        }

        # Add each extension to the VM and validate instance view has succeeded status
        # Each extension will be added with settings to echo it's assigned test_guid:
        # {
        #     "source": {
        #         "script": f"echo {t.test_guid}"
        #     }
        # }
        MultiConfigExt.enable_and_validate_test_cases(test_cases.values())

        # TODO validate that the extension output has expected stdout/message
        MultiConfigExt.assert_guids_in_instance_view((test_cases.values()))


        # TODO Re-enable MCExt3 with new test_guid and add MCExt4 and validate instance view has correct status
        test_cases_2 = [

        ]

        # TODO validate that the new extensions output has expected stdout/message

        # TODO validate ALL extensions are in instance view, and no additional extensoins are there

        # TODO remove each ext

        # TODO validate no extension still in instance view


if __name__ == "__main__":
    MultiConfigExt.run_from_command_line()
