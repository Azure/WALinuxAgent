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
#
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from assertpy import fail
from azure.mgmt.compute.models import VirtualMachineExtensionInstanceView

from tests_e2e.tests.lib.agent_test import AgentTest, TestSkipped
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


class ExtSequencing(AgentTest):
    def get_dependency_map(self, extensions: List[Dict[str, Any]]) -> dict:
        dependency_map = dict()

        for ext in extensions:
            ext_name = ext['name']
            provisioned_after = ext['properties'].get('provisionAfterExtensions')
            dependency_map[ext_name] = provisioned_after

        return dependency_map

    @staticmethod
    def __get_time(ext: VirtualMachineExtensionInstanceView):
        if ext.statuses[0].message is not None:
            # In our tests, for CSE and RunCommand, we would execute this command to get the time when it was enabled -
            # echo 'GUID: $(date +%Y-%m-%dT%H:%M:%S.%3NZ)'
            match = re.search(r"([\d-]+T[\d:.]+Z)", ext.statuses[0].message)
            if match is not None:
                return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")

        # If nothing else works, just return the minimum datetime
        return datetime.min

    def get_sorted_extension_names(self, extensions: List[VirtualMachineExtensionInstanceView]):
        # Log the extension enabled datetime
        for ext in extensions:
            ext.time = self.__get_time(ext)
            log.info("Extension {0} Status from instance view: {1}".format(ext.name, ext.statuses[0]))

        # sort the extensions based on their enabled datetime
        sorted_extensions = sorted(extensions, key=lambda ext_: ext_.time)
        log.info("Sorted extension names with time: {0}".format(
            ', '.join(["{0}: {1}".format(ext.name, ext.time) for ext in sorted_extensions])))
        sorted_extension_names = [ext.name for ext in sorted_extensions]
        return sorted_extension_names

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
        ssh: SshClient = self._context.create_ssh_client()
        if not VmExtensionIds.VmAccess.supports_distro(ssh.run_command("uname -a")):
            raise TestSkipped("Currently VMAccess is not supported on this distro")

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
        log.info("The extensions on the scale set instance are: {0}".format(extensions))

        # Get the dependency map for the extensions on the VM
        dependency_map = self.get_dependency_map(extensions)
        log.info("")
        log.info("The dependency map of the extensions is: {0}".format(dependency_map))

        # Get the extensions from the instance view for the VM
        log.info("")
        vm: VirtualMachineClient = VirtualMachineClient(self._context.vm)
        instance_view_extensions = vm.get_instance_view().extensions

        # Sort the VM extensions by the time they were enabled
        sorted_extension_names = self.get_sorted_extension_names(instance_view_extensions)

        # Validate that the extensions were enabled in the correct order
        result = self.validate_extension_sequencing(dependency_map, sorted_extension_names)
        if not result:
            fail("Extensions were not enabled in the correct order")


if __name__ == "__main__":
    ExtSequencing.run_from_command_line()
