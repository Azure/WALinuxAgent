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
from typing import Dict, Callable, Any

from assertpy import fail
from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class MultiConfigExt(AgentTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient, get_settings: Callable[[str], Dict[str, str]]):
            self.extension = extension
            self.get_settings = get_settings
            self.test_guid: str = str(uuid.uuid4())

    def enable_and_assert_test_cases(self, cases_to_enable: Dict[str, TestCase], cases_to_assert: Dict[str, TestCase], delete_extensions: bool = False):
        for resource_name, test_case in cases_to_enable.items():
            log.info("")
            log.info("Adding {0} to the test VM. guid={1}".format(resource_name, test_case.test_guid))
            test_case.extension.enable(settings=test_case.get_settings(test_case.test_guid))
            test_case.extension.assert_instance_view()

        log.info("")
        log.info("Check that each extension has the expected guid in its status message...")
        for resource_name, test_case in cases_to_assert.items():
            log.info("")
            log.info("Checking {0} has expected status message with {1}".format(resource_name, test_case.test_guid))
            test_case.extension.assert_instance_view(expected_message=f"{test_case.test_guid}")

        # Delete each extension on the VM
        if delete_extensions:
            log.info("")
            log.info("Delete each extension...")
            self.delete_extensions(cases_to_assert)

    def delete_extensions(self, test_cases: Dict[str, TestCase]):
        for resource_name, test_case in test_cases.items():
            log.info("")
            log.info("Deleting {0} from the test VM".format(resource_name))
            test_case.extension.delete()

        log.info("")
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        instance_view: VirtualMachineInstanceView = vm.get_instance_view()
        if instance_view.extensions is not None:
            for ext in instance_view.extensions:
                if ext.name in test_cases.keys():
                    fail("Extension was not deleted: \n{0}".format(ext))
        log.info("")
        log.info("All extensions were successfully deleted.")

    def run(self):
        # Create 3 different RCv2 extensions and a single config extension (CSE) and assign each a unique guid. Each
        # extension will have settings that echo its assigned guid. We will use this guid to verify the extension
        # statuses later.
        mc_settings: Callable[[Any], Dict[str, Dict[str, str]]] = lambda s: {
            "source": {"script": f"echo {s}"}}
        sc_settings: Callable[[Any], Dict[str, str]] = lambda s: {'commandToExecute': f"echo {s}"}

        test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt1": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt1"), mc_settings),
            "MCExt2": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt2"), mc_settings),
            "MCExt3": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt3"), mc_settings),
            "CSE": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript), sc_settings)
        }

        # Add each extension to the VM and validate the instance view has succeeded status with its assigned guid in the
        # status message
        log.info("")
        log.info("Add CSE and 3 instances of RCv2 to the VM. Each instance will echo a unique guid...")
        self.enable_and_assert_test_cases(cases_to_enable=test_cases, cases_to_assert=test_cases)

        # Update MCExt3 and CSE with new guids and add a new instance of RCv2 to the VM
        updated_test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt3": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt3"), mc_settings),
            "MCExt4": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt4"), mc_settings),
            "CSE": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript), sc_settings)
        }
        test_cases.update(updated_test_cases)

        # Enable only the updated extensions, verify every extension has the correct test guid is in status message, and
        # remove all extensions from the test vm
        log.info("")
        log.info("Update MCExt3 and CSE with new guids and add a new instance of RCv2 to the VM...")
        self.enable_and_assert_test_cases(cases_to_enable=updated_test_cases, cases_to_assert=test_cases,
                                          delete_extensions=True)

        # Enable, verify, and remove only multi config extensions
        log.info("")
        log.info("Add only multi-config extensions to the VM...")
        mc_test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "MCExt5": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt5"), mc_settings),
            "MCExt6": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="MCExt6"), mc_settings)
        }
        self.enable_and_assert_test_cases(cases_to_enable=mc_test_cases, cases_to_assert=mc_test_cases,
                                          delete_extensions=True)

        # Enable, verify, and delete only single config extensions
        log.info("")
        log.info("Add only single-config extension to the VM...")
        sc_test_cases: Dict[str, MultiConfigExt.TestCase] = {
            "CSE": MultiConfigExt.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript), sc_settings)
        }
        self.enable_and_assert_test_cases(cases_to_enable=sc_test_cases, cases_to_assert=sc_test_cases,
                                          delete_extensions=True)


if __name__ == "__main__":
    MultiConfigExt.run_from_command_line()
