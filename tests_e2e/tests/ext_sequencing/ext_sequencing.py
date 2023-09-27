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
# This test adds extensions with multiple dependencies to a VMSS using the 'provisionAfterExtensions' property and
# validates they are enabled in order of dependencies.
# TODO: Currently Flexible VMSS does not support UpgradePolicy. Once UpgradePolicy is supported, this scenario should
#  be improved to update the scale set model with new extensions/dependencies and validate the order in which they were
#  enabled
#
import json
import random
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from assertpy import fail
from azure.core.exceptions import HttpResponseError
from azure.mgmt.compute.models import VirtualMachineExtensionInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmssIdentifier, VmIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VirtualMachineScaleSetClient


class ExtSequencing(AgentTest):
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def get_sorted_extension_names(self, extensions: List[VirtualMachineExtensionInstanceView], ssh_client: SshClient):
        # Log the extension enabled datetime
        for ext in extensions:
            enabled_time = ssh_client.run_command(f"ext_sequencing-get_ext_enable_time.py --ext_type {ext.type}", use_sudo=True)
            ext.time = datetime.strptime(enabled_time.replace('\n', ''), u'%Y-%m-%d %H:%M:%S')
            log.info("Extension {0} enabled time: {1}".format(ext.name, ext.time))

        # sort the extensions based on their enabled datetime
        sorted_extensions = sorted(extensions, key=lambda ext_: ext_.time)
        log.info("Sorted extension names with time: {0}".format(
            ', '.join(["{0}: {1}".format(ext.name, ext.time) for ext in sorted_extensions])))
        sorted_extension_names = [ext.name for ext in sorted_extensions]
        return sorted_extension_names

    @staticmethod
    def delete_extension_with_dependencies_should_fail(vmss: VirtualMachineScaleSetClient, dependency_map: dict):
        # Randomly choose an extension that has dependencies on it to remove
        ext_to_remove = None
        for ext in dependency_map:
            if dependency_map[ext]:
                ext_to_remove = random.choice(dependency_map[ext])
                break
        if ext_to_remove:
            try:
                vmss.delete_extension(ext_to_remove)
            except HttpResponseError as e:
                if "(BadRequest)" in e.message and "provisionAfterExtensions" in e.message:
                    log.info("Removing {0} failed as expected".format(ext_to_remove))
                else:
                    fail("Unexpected error removing extension from VMSS: {0}".format(e))
            except Exception as e:
                fail("Unexpected error removing extension from VMSS: {0}".format(e))
        else:
            log.info("There are no extensions which have dependencies to delete")

    @staticmethod
    def delete_extension_without_dependencies_should_succeed(vmss: VirtualMachineScaleSetClient, dependency_map: dict):
        # Randomly choose an extension that has no dependencies on it to remove
        ext_to_remove = None
        for ext in dependency_map:
            can_be_removed = True
            for ext_key in dependency_map:
                dependencies = dependency_map.get(ext_key)
                if dependencies is not None and ext in dependencies:
                    can_be_removed = False
            if can_be_removed:
                ext_to_remove = ext
                break
        if ext_to_remove:
            vmss.delete_extension(ext_to_remove)
            log.info("Deleting {0} succeeded as expected".format(ext_to_remove))
        else:
            log.info("There are no extensions which do not have dependencies to delete")

    @staticmethod
    def get_dependency_map(extensions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        dependency_map = dict()

        for ext in extensions:
            ext_name = ext['name']
            provisioned_after = ext['properties'].get('provisionAfterExtensions')
            dependency_map[ext_name] = provisioned_after

        return dependency_map

    @staticmethod
    def validate_extension_sequencing(dependency_map, sorted_extension_names) -> bool:
        installed_ext = dict()

        # Iterate through the extensions in the enabled order and validate if their depending
        # extensions are already enabled prior to that.
        for ext in sorted_extension_names:
            # Check if the depending extension are already installed
            if ext not in dependency_map:
                log.info("Unwanted extension found in Instance view: {0}".format(ext))
                return False
            if dependency_map[ext] is not None:
                for dep in dependency_map[ext]:
                    if installed_ext.get(dep) is None:
                        # The depending extension is not installed prior to the current extension
                        log.info("{0} is not installed prior to {1}".format(dep, ext))
                        return False

            # Mark the current extension as installed
            installed_ext[ext] = ext

        log.info("Validated extension sequencing")
        return True

    def run(self):
        # Get the extensions that were added to the scale set instances at VMSS creation
        template_file_path = Path(__file__).parent.parent.parent / "orchestrator/lib/templates/ext_seq_vmss_template.json"
        with open(template_file_path, "r") as f:
            template: Dict[str, Any] = json.load(f)
        vmss_resource = {}
        for resource in template['resources']:
            if resource['type'] == "Microsoft.Compute/virtualMachineScaleSets":
                vmss_resource = resource
        extensions = vmss_resource['properties']['virtualMachineProfile']['extensionProfile']['extensions']
        log.info("")
        log.info("The following extensions were added to the scale set model at creation:")
        for ext in extensions:
            log.info(f"{ext}")

        # Get the dependency map for the extensions on the VM
        dependency_map = self.get_dependency_map(extensions)
        log.info("")
        log.info("The dependency map of the extensions is:")
        for ext, dependencies in dependency_map.items():
            dependency_list = "N/A" if not dependencies else ', '.join(dependencies)
            log.info("{0}: {1}".format(ext, dependency_list))

        vmss = VirtualMachineScaleSetClient(
            VmssIdentifier(
                cloud=self._context.vm.cloud,
                location=self._context.vm.location,
                subscription=self._context.vm.subscription,
                resource_group=self._context.vm.resource_group,
                name=self._context.vm.resource_group.replace('-', '').lower()
            )
        )
        log.info("")
        vms = vmss.get_virtual_machines()
        for vm_instance in vms:
            log.info("")
            log.info("Validate extension sequencing on instance {0}...".format(vm_instance.get('name')))
            instance_ssh_client = SshClient(ip_address=vm_instance.get('ip'), username=self._ssh_client._username,
                                            private_key_file=self._ssh_client._private_key_file)

            # Get the extensions from the instance view for the VM
            log.info("")
            vm: VirtualMachineClient = VirtualMachineClient(VmIdentifier(
                cloud=self._context.vm.cloud,
                location=self._context.vm.location,
                subscription=self._context.vm.subscription,
                resource_group=self._context.vm.resource_group,
                name=vm_instance.get('name')
            ))
            instance_view_extensions = vm.get_instance_view().extensions

            # Sort the VM extensions by the time they were enabled
            sorted_extension_names = self.get_sorted_extension_names(instance_view_extensions, instance_ssh_client)

            # Validate that the extensions were enabled in the correct order
            result = self.validate_extension_sequencing(dependency_map, sorted_extension_names)
            if not result:
                fail("Extensions were not enabled in the correct order")

        # Removing an extension from the VMSS which other extensions are dependent on should fail
        log.info("")
        log.info("Delete an extension from the VMSS which other extensions are dependent on...")
        self.delete_extension_with_dependencies_should_fail(vmss, dependency_map)

        # Removing an extension from the VMSS which no other extensions are dependent on should succeed
        log.info("")
        log.info("Delete an extension from the VMSS which no other extension is dependent on...")
        self.delete_extension_without_dependencies_should_succeed(vmss, dependency_map)


if __name__ == "__main__":
    ExtSequencing.run_from_command_line()
