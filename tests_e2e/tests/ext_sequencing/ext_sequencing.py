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
import re
import uuid
from datetime import datetime
from typing import List, Dict, Any

from assertpy import fail
from azure.mgmt.compute.models import VirtualMachineScaleSetVMExtensionsSummary

from tests_e2e.tests.ext_sequencing.ext_seq_test_cases import add_one_dependent_ext_without_settings, add_two_extensions_with_dependencies, \
    remove_one_dependent_extension, remove_all_dependencies, add_one_dependent_extension, \
    add_single_dependencies, remove_all_dependent_extensions, add_failing_dependent_extension_with_one_dependency, add_failing_dependent_extension_with_two_dependencies
from tests_e2e.tests.lib.agent_test import AgentVmssTest, TestSkipped
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VmssInstanceIpAddress
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient
from tests_e2e.tests.lib.ssh_client import SshClient


class ExtSequencing(AgentVmssTest):

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._scenario_start = datetime.min

    # Cases to test different dependency scenarios
    _test_cases = [
        add_one_dependent_ext_without_settings,
        add_two_extensions_with_dependencies,
        # remove_one_dependent_extension should only be run after another test case which has RunCommandLinux in the
        # model
        remove_one_dependent_extension,
        # remove_all_dependencies should only be run after another test case which has extension dependencies in the
        # model
        remove_all_dependencies,
        add_one_dependent_extension,
        add_single_dependencies,
        # remove_all_dependent_extensions should only be run after another test case which has dependent extension in
        # the model
        remove_all_dependent_extensions,
        add_failing_dependent_extension_with_one_dependency,
        add_failing_dependent_extension_with_two_dependencies
    ]

    @staticmethod
    def _get_dependency_map(extensions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        dependency_map: Dict[str, Dict[str, Any]] = dict()

        for ext in extensions:
            ext_name = ext['name']
            provisioned_after = ext['properties'].get('provisionAfterExtensions')
            depends_on = provisioned_after if provisioned_after else []
            # We know an extension should fail if commandToExecute is exactly "exit 1"
            ext_settings = ext['properties'].get("settings")
            ext_command = ext['properties']['settings'].get("commandToExecute") if ext_settings else None
            should_fail = ext_command == "exit 1"
            dependency_map[ext_name] = {"should_fail": should_fail, "depends_on": depends_on}

        return dependency_map

    @staticmethod
    def _get_sorted_extension_names(extensions: List[VirtualMachineScaleSetVMExtensionsSummary], ssh_client: SshClient, test_case_start: datetime) -> List[str]:
        # Using VmExtensionIds to get publisher for each ext to be used in remote script
        extension_full_names = {
            "AzureMonitorLinuxAgent": VmExtensionIds.AzureMonitorLinuxAgent,
            "RunCommandLinux": VmExtensionIds.RunCommand,
            "CustomScript": VmExtensionIds.CustomScript
        }
        enabled_times = []
        for ext in extensions:
            # Only check extensions which succeeded provisioning
            if "succeeded" in ext.statuses_summary[0].code:
                enabled_time = ssh_client.run_command(f"ext_sequencing-get_ext_enable_time.py --ext '{extension_full_names[ext.name]}'", use_sudo=True)
                formatted_time = datetime.strptime(enabled_time.strip(), u'%Y-%m-%dT%H:%M:%SZ')
                if formatted_time < test_case_start:
                    fail("Extension {0} was not enabled".format(extension_full_names[ext.name]))
                enabled_times.append(
                    {
                        "name": ext.name,
                        "enabled_time": formatted_time
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
    def _validate_extension_sequencing(dependency_map: Dict[str, Dict[str, Any]], sorted_extension_names: List[str], relax_check: bool):
        installed_ext = dict()

        # Iterate through the extensions in the enabled order and validate if their depending extensions are already
        # enabled prior to that.
        for ext in sorted_extension_names:
            # Check if the depending extension are already installed
            if ext not in dependency_map:
                # There should not be any unexpected extensions on the scale set, even in the case we share the VMSS,
                # because we update the scale set model with the extensions. Any extensions that are not in the scale
                # set model would be disabled.
                fail("Unwanted extension found in VMSS Instance view: {0}".format(ext))
            if dependency_map[ext] is not None:
                dependencies = dependency_map[ext].get('depends_on')
                for dep in dependencies:
                    if installed_ext.get(dep) is None:
                        # The depending extension is not installed prior to the current extension
                        if relax_check:
                            log.info("{0} is not installed prior to {1}".format(dep, ext))
                        else:
                            fail("{0} is not installed prior to {1}".format(dep, ext))

            # Mark the current extension as installed
            installed_ext[ext] = ext

        # Validate that only extensions expected to fail, and their dependent extensions, failed
        for ext, details in dependency_map.items():
            failing_ext_dependencies = [dep for dep in details['depends_on'] if dependency_map[dep]['should_fail']]
            if ext not in installed_ext:
                if details['should_fail']:
                    log.info("Extension {0} failed as expected".format(ext))
                elif failing_ext_dependencies:
                    log.info("Extension {0} failed as expected because it is dependent on {1}".format(ext, ' and '.join(failing_ext_dependencies)))
                else:
                    fail("{0} unexpectedly failed. Only extensions that are expected to fail or depend on a failing extension should fail".format(ext))

        log.info("Validated extension sequencing")

    def run(self):
        instances_ip_address: List[VmssInstanceIpAddress] = self._context.vmss.get_instances_ip_address()
        ssh_clients: Dict[str, SshClient] = dict()
        for instance in instances_ip_address:
            ssh_clients[instance.instance_name] = SshClient(ip_address=instance.ip_address, username=self._context.username, identity_file=self._context.identity_file)

        if not VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(next(iter(ssh_clients.values())).run_command("uname -a")):
            raise TestSkipped("Currently AzureMonitorLinuxAgent is not supported on this distro")

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

        for case in self._test_cases:
            test_case_start = datetime.now()
            if self._scenario_start == datetime.min:
                self._scenario_start = test_case_start

            # Assign unique guid to forceUpdateTag for each extension to make sure they're always unique to force CRP
            # to generate a new sequence number each time
            test_guid = str(uuid.uuid4())
            extensions = case()
            for ext in extensions:
                ext["properties"].update({
                    "forceUpdateTag": test_guid
                })

            # We update the extension template here with extensions that are specific to the scenario that we want to
            # test out
            log.info("")
            log.info("Test case: {0}".format(case.__name__.replace('_', ' ')))
            ext_template = copy.deepcopy(base_extension_template)
            ext_template['resources'][0]['properties']['virtualMachineProfile']['extensionProfile'][
                'extensions'] = extensions

            # Log the dependency map for the extensions in this test case
            dependency_map = self._get_dependency_map(extensions)
            log.info("")
            log.info("The dependency map of the extensions for this test case is:")
            for ext, details in dependency_map.items():
                dependencies = details.get('depends_on')
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
                # fail. We know an extension should fail if "failing" is in the case name. Otherwise, report the
                # failure.
                deployment_failure_pattern = r"[\s\S]*\"details\": [\s\S]* \"code\": \"(?P<code>.*)\"[\s\S]* \"message\": \"(?P<msg>.*)\"[\s\S]*"
                msg_pattern = r"Multiple VM extensions failed to be provisioned on the VM. Please see the VM extension instance view for other failures. The first extension failed due to the error: VM Extension '.*' is marked as failed since it depends upon the VM Extension 'CustomScript' which has failed."
                deployment_failure_match = re.match(deployment_failure_pattern, str(e))
                if "failing" not in case.__name__:
                    fail("Extension template deployment unexpectedly failed: {0}".format(e))
                elif not deployment_failure_match or deployment_failure_match.group("code") != "VMExtensionProvisioningError" or not re.match(msg_pattern, deployment_failure_match.group("msg")):
                    fail("Extension template deployment failed as expected, but with an unexpected error: {0}".format(e))

            # Get the extensions on the VMSS from the instance view
            log.info("")
            instance_view_extensions = self._context.vmss.get_instance_view().extensions

            # Validate that the extensions were enabled in the correct order on each instance of the scale set
            for instance_name, ssh_client in ssh_clients.items():
                log.info("")
                log.info("Validate extension sequencing on {0}:{1}...".format(instance_name, ssh_client.ip_address))

                # Sort the VM extensions by the time they were enabled
                sorted_extension_names = self._get_sorted_extension_names(instance_view_extensions, ssh_client, test_case_start)

                # Validate that the extensions were enabled in the correct order. We relax this check if no settings
                # are provided for a dependent extension, since the guest agent currently ignores dependencies in this
                # case.
                relax_check = True if "settings" in case.__name__ else False
                self._validate_extension_sequencing(dependency_map, sorted_extension_names, relax_check)

            log.info("------")

    def get_ignore_errors_before_timestamp(self) -> datetime:
        # Ignore errors in the agent log before the first test case starts
        return self._scenario_start

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # WARNING ExtHandler ExtHandler Missing dependsOnExtension on extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent
            # This message appears when an extension doesn't depend on another extension
            #
            {
                'message': r"Missing dependsOnExtension on extension .*"
            },
            #
            # WARNING ExtHandler ExtHandler Extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent does not have any settings. Will ignore dependency (dependency level: 1)
            # We currently ignore dependencies for extensions without settings
            #
            {
                'message': r"Extension .* does not have any settings\. Will ignore dependency \(dependency level: \d\)"
            },
            #
            # 2023-10-31T17:46:59.675959Z WARNING ExtHandler ExtHandler Dependent extension Microsoft.Azure.Extensions.CustomScript failed or timed out, will skip processing the rest of the extensions
            # We intentionally make CustomScript fail to test that dependent extensions are skipped
            #
            {
                'message': r"Dependent extension Microsoft.Azure.Extensions.CustomScript failed or timed out, will skip processing the rest of the extensions"
            },
            #
            # 2023-10-31T17:48:13.349214Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Extensions.CustomScript, op=ExtensionProcessing, message=Dependent Extension Microsoft.Azure.Extensions.CustomScript did not succeed. Status was error, duration=0
            # We intentionally make CustomScript fail to test that dependent extensions are skipped
            #
            {
                'message': r"Event: name=Microsoft.Azure.Extensions.CustomScript, op=ExtensionProcessing, message=Dependent Extension Microsoft.Azure.Extensions.CustomScript did not succeed. Status was error, duration=0"
            },
            #
            # 2023-10-31T17:47:07.689083Z WARNING ExtHandler ExtHandler [PERIODIC] This status is being reported by the Guest Agent since no status file was reported by extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent: [ExtensionStatusError] Status file /var/lib/waagent/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.28.11/status/6.status does not exist
            # We expect extensions that are dependent on a failing extension to not report status
            #
            {
                'message': r"\[PERIODIC\] This status is being reported by the Guest Agent since no status file was reported by extension .*: \[ExtensionStatusError\] Status file \/var\/lib\/waagent\/.*\/status\/\d.status does not exist"
            },
            #
            # 2023-10-31T17:48:11.306835Z WARNING ExtHandler ExtHandler A new goal state was received, but not all the extensions in the previous goal state have completed: [('Microsoft.Azure.Extensions.CustomScript', 'error'), ('Microsoft.Azure.Monitor.AzureMonitorLinuxAgent', 'transitioning'), ('Microsoft.CPlat.Core.RunCommandLinux', 'success')]
            # This message appears when the previous test scenario had failing extensions due to extension dependencies
            #
            {
                'message': r"A new goal state was received, but not all the extensions in the previous goal state have completed: \[(\(u?'.*', u?'(error|transitioning|success)'\),?)+\]"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtSequencing.run_from_command_line()
