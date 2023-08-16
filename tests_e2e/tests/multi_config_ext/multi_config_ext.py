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
import json
import uuid
from typing import Dict

from assertpy import fail
from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class MultiConfigExt(AgentTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient):
            self.extension = extension
            self.test_guid: str = str(uuid.uuid4())

    def enable_extensions(self, test_cases: Dict[str, TestCase]):
        for resource_name, test_case in test_cases.items():
            log.info("")
            log.info("Adding {0} to the test VM. guid={1}".format(resource_name, test_case.test_guid))
            test_case.extension.enable(settings={
                "source": {
                    "script": f"echo {test_case.test_guid}"
                }
            })
            test_case.extension.assert_instance_view()

    def assert_expected_guids_in_ext_status(self, test_cases: Dict[str, TestCase]):
        for resource_name, test_case in test_cases.items():
            log.info("")
            log.info("Checking {0} has expected status message with {1}".format(resource_name, test_case.test_guid))
            test_case.extension.assert_instance_view(expected_message=f"{test_case.test_guid}")

    def run(self):
        # Create 3 different RCv2 extensions and assign each a unique guid. We will use this guid to verify the
        # extension status later
        test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt1": MultiConfigExt.TestCase(VirtualMachineExtensionClient(self._context.vm,
                                                                            VmExtensionIds.RunCommandHandler,
                                                                            resource_name="MCExt1")),
            "MCExt2": MultiConfigExt.TestCase(VirtualMachineExtensionClient(self._context.vm,
                                                                            VmExtensionIds.RunCommandHandler,
                                                                            resource_name="MCExt2")),
            "MCExt3": MultiConfigExt.TestCase(VirtualMachineExtensionClient(self._context.vm,
                                                                            VmExtensionIds.RunCommandHandler,
                                                                            resource_name="MCExt3"))
        }

        # Add each extension to the VM and validate instance view has succeeded status.
        # Each extension will be added with settings to echo its assigned test_guid:
        # {
        #     "source": {
        #         "script": f"echo {t.test_guid}"
        #     }
        # }
        log.info("")
        log.info("Add 3 instances of RCv2 to the VM. Each instance will echo a unique guid...")
        self.enable_extensions(test_cases=test_cases)
        log.info("")
        log.info("Check that each extension has the expected guid in its status message...")
        self.assert_expected_guids_in_ext_status(test_cases=test_cases)

        # Update MCExt3 with a new guid and add a new instance of RCv2 to the VM
        updated_test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt3": MultiConfigExt.TestCase(VirtualMachineExtensionClient(self._context.vm,
                                                                            VmExtensionIds.RunCommandHandler,
                                                                            resource_name="MCExt3")),
            "MCExt4": MultiConfigExt.TestCase(VirtualMachineExtensionClient(self._context.vm,
                                                                            VmExtensionIds.RunCommandHandler,
                                                                            resource_name="MCExt4"))
        }
        test_cases.update(updated_test_cases)

        log.info("")
        log.info("Update MCExt3 with new guid and add a new instance of RCv2 to the VM...")
        self.enable_extensions(test_cases=updated_test_cases)
        log.info("")
        log.info("Check that each extension has the expected guid in its status message...")
        self.assert_expected_guids_in_ext_status(test_cases=test_cases)

        # Delete each extension on the VM and assert that there are no unexpected extensions left
        log.info("")
        log.info("Delete each instance of RCv2...")
        for resource_name, test_case in test_cases.items():
            log.info("")
            log.info("Deleting {0} from the test VM".format(resource_name))
            test_case.extension.delete()

        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        instance_view: VirtualMachineInstanceView = vm.get_instance_view()
        if instance_view.extensions is not None and any(instance_view.extensions):
            fail("Unwanted extension found: \n{0}".format(json.dumps(instance_view.serialize(), indent=2)))
        log.info("")
        log.info("All instances of RCv2 were successfully deleted, and no unexpected extensions were found in the "
                 "instance view.")


if __name__ == "__main__":
    MultiConfigExt.run_from_command_line()
