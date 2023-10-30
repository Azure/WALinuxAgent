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
import copy
import uuid
from datetime import datetime
from typing import List, Dict, Any

from assertpy import fail, assert_that
from azure.mgmt.compute.models import VirtualMachineScaleSetVMExtensionsSummary

from tests_e2e.tests.ext_sequencing.ext_seq_test_cases import add_one_dependent_ext_without_settings, add_two_extensions_with_dependencies, \
    remove_one_dependent_extension, remove_all_dependencies, add_one_dependent_extension, \
    add_single_dependencies, remove_all_dependent_extensions, add_failing_dependent_extension_with_one_dependency, add_failing_dependent_extension_with_two_dependencies
from tests_e2e.tests.lib.agent_test import AgentVmssTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient
from tests_e2e.tests.lib.ssh_client import SshClient


class ExtSequencing(AgentVmssTest):
    # Cases to test different dependency scenarios
    test_cases = [
        add_one_dependent_ext_without_settings,
        add_two_extensions_with_dependencies,
        remove_one_dependent_extension,
        remove_all_dependencies,
        add_one_dependent_extension,
        add_single_dependencies,
        remove_all_dependent_extensions,
        add_failing_dependent_extension_with_one_dependency,
        add_failing_dependent_extension_with_two_dependencies
    ]

    @staticmethod
    def get_dependency_map(extensions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        dependency_map = dict()

        for ext in extensions:
            ext_name = ext['name']
            provisioned_after = ext['properties'].get('provisionAfterExtensions')
            dependency_map[ext_name] = provisioned_after

        return dependency_map

    @staticmethod
    def validate_dependent_extensions_fail(dependency_map: Dict[str, List[str]], extensions: List[VirtualMachineScaleSetVMExtensionsSummary]):
        failed_extensions = [ext.name for ext in extensions if "failed" in ext.statuses_summary[0].code]
        for ext, dependencies in dependency_map.items():
            for dep in dependencies:
                if dep in failed_extensions:
                    assert_that(ext in failed_extensions).described_as("{0} dependent on failing extension {1} should also fail")

        for ext in extensions:
            dependencies = dependency_map[ext.name]
            assert_that("failed" in ext.statuses_summary[0].code).described_as(
                    "CustomScript should have failed to enable").is_true()
            if "CustomScript" in dependency_map[ext.name]:
                assert_that("failed" in ext.statuses_summary[0].code).described_as(
                    "{0} should have failed to enable as it's dependent on CustomScript".format(ext.name)).is_true()
        log.info("Validated that all extensions dependent on a failing extension also failed")

    @staticmethod
    def get_sorted_extension_names(extensions: List[VirtualMachineScaleSetVMExtensionsSummary], ssh_client: SshClient) -> List[str]:
        # Using VmExtensionIds to get publisher for each ext to be used in remote script
        extension_full_names = {
            "AzureMonitorLinuxAgent": VmExtensionIds.AzureMonitorLinuxAgent,
            "RunCommandLinux": VmExtensionIds.RunCommand,
            "CustomScript": VmExtensionIds.CustomScript
        }
        enabled_times = []
        for ext in extensions:
            # Only add extensions which succeeded provisioning
            if "succeeded" in ext.statuses_summary[0].code:
                enabled_time = ssh_client.run_command(f"ext_sequencing-get_ext_enable_time.py --ext_type {extension_full_names[ext.name]}",
                                                      use_sudo=True)
                enabled_times.append(
                    {
                        "name": ext.name,
                        "enabled_time": datetime.strptime(enabled_time.replace('\n', ''), u'%Y-%m-%d %H:%M:%S')
                     }
                )

        # sort the extensions based on their enabled datetime
        sorted_extensions = sorted(enabled_times, key=lambda ext_: ext_["enabled_time"])
        log.info("")
        log.info("Extensions sorted by time they were enabled: {0}".format(
            ', '.join(["{0}: {1}".format(ext["name"], ext["enabled_time"]) for ext in sorted_extensions])))
        sorted_extension_names = [ext["name"] for ext in sorted_extensions]
        return sorted_extension_names

    @staticmethod
    def validate_extension_sequencing(dependency_map: Dict[str, List[str]], sorted_extension_names: List[str]):
        installed_ext = dict()

        # Iterate through the extensions in the enabled order and validate if their depending extensions are already
        # enabled prior to that.
        for ext in sorted_extension_names:
            # Check if the depending extension are already installed
            if ext not in dependency_map:
                fail("Unwanted extension found in VMSS Instance view: {0}".format(ext))
            if dependency_map[ext] is not None:
                for dep in dependency_map[ext]:
                    if installed_ext.get(dep) is None:
                        # The depending extension is not installed prior to the current extension
                        fail("{0} is not installed prior to {1}".format(dep, ext))

            # Mark the current extension as installed
            installed_ext[ext] = ext

        log.info("Validated extension sequencing")

    def run(self):
        # This is the base ARM template that's used for deploying extensions for this scenario
        base_extension_template = {
            "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachineScaleSets",
                    "name": f"{self._context.vmss.name}",
                    "location": "[resourceGroup().location]",
                    "apiVersion": "2018-06-01",
                    "properties": {
                        "virtualMachineProfile": {
                            "extensionProfile": {
                                "extensions": []
                            }
                        }
                    }
                }
            ]
        }

        for case in self.test_cases:
            # Update the settings for each extension in this scenario to make sure they're always unique to force CRP
            # to generate a new sequence number each time
            test_guid = str(uuid.uuid4())
            deployment_should_fail = "failing" in case.__name__
            extensions = case()
            for ext in extensions:
                # We only want to update the settings if they are empty (so we don't overwrite any failing script
                # scenarios)
                if "settings" in ext["properties"] and not ext["properties"]["settings"]:
                    ext["properties"]["settings"].update({
                        "commandToExecute": "echo \"{0}: $(date +%Y-%m-%dT%H:%M:%S.%3NZ)\"".format(test_guid)
                    })

            # We update the extension template here with extensions that are specific to the scenario that we want to
            # test out
            log.info("")
            log.info("Test case: {0}".format(case.__name__.replace('_', ' ')))
            ext_template = copy.deepcopy(base_extension_template)
            ext_template['resources'][0]['properties']['virtualMachineProfile']['extensionProfile'][
                'extensions'] = extensions

            # Log the dependency map for the extensions in this test case
            dependency_map = self.get_dependency_map(extensions)
            log.info("")
            log.info("The dependency map of the extensions for this test case is:")
            for ext, dependencies in dependency_map.items():
                dependency_list = "-" if not dependencies else ' and '.join(dependencies)
                log.info("{0} depends on {1}".format(ext, dependency_list))

            # Deploy updated extension template to the scale set.
            log.info("")
            log.info("Deploying extensions with the above dependencies to the scale set...")
            rg_client = ResourceGroupClient(self._context.vmss.cloud, self._context.vmss.subscription,
                                            self._context.vmss.resource_group, self._context.vmss.location)
            try:
                rg_client.deploy_template(template=ext_template)
            except Exception as e:
                # We only expect to catch an exception during deployment if we are forcing one of the extensions to
                # fail. Otherwise, report the failure.
                if not deployment_should_fail:
                    fail("Extension template deployment unexpectedly failed: {0}".format(e))

            # Get the extensions on the VMSS from the instance view
            log.info("")
            instance_view_extensions = self._context.vmss.get_instance_view().extensions

            # If deployment failed, assert that all and only dependent extensions failed
            if deployment_should_fail:
                self.validate_dependent_extensions_fail(dependency_map, instance_view_extensions)

            # Validate that the extensions were enabled in the correct order on each instance of the scale set
            for address in self._context.vmss.get_instances_ip_address():
                ssh_client: SshClient = SshClient(ip_address=address.ip_address, username=self._context.username, identity_file=self._context.identity_file)

                log.info("")
                log.info("Validate extension sequencing on {0}...".format(address.ip_address))

                # Sort the VM extensions by the time they were enabled
                sorted_extension_names = self.get_sorted_extension_names(instance_view_extensions, ssh_client)

                # Validate that the extensions were enabled in the correct order
                self.validate_extension_sequencing(dependency_map, sorted_extension_names)

            log.info("------")


if __name__ == "__main__":
    ExtSequencing.run_from_command_line()
