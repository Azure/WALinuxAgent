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
# This test adds extensions with multiple dependencies to a VMSS and checks that extensions fail and report status
# as expected when blocked by extension policy.

import copy
import json
import random
import re
import os
import uuid
import time
from datetime import datetime
from typing import List, Dict, Any

from azurelinuxagent.common.future import datetime_min_utc

from azurelinuxagent.common.future import UTC

from assertpy import fail
from tests_e2e.tests.lib.agent_test import AgentVmssTest, TestSkipped
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VmssInstanceIpAddress
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.ext_policy.policy_dependencies_cases import _should_fail_single_config_depends_on_disallowed_no_config, \
        _should_fail_single_config_depends_on_disallowed_single_config, \
        _should_succeed_single_config_depends_on_no_config, \
        _should_succeed_single_config_depends_on_single_config
        # TODO: RunCommandHandler is unable to be uninstalled properly, so these tests are currently disabled. Uncomment
        # the below imports after re-enabling the test.
        # _should_fail_single_config_depends_on_disallowed_multi_config,
        # _should_fail_multi_config_depends_on_disallowed_single_config,
        # _should_fail_multi_config_depends_on_disallowed_no_config,

class ExtPolicyWithDependencies(AgentVmssTest):
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._scenario_start = datetime_min_utc

    # Cases to test different dependency scenarios
    _test_cases = [
        _should_fail_single_config_depends_on_disallowed_single_config,
        _should_fail_single_config_depends_on_disallowed_no_config,
        # TODO: RunCommandHandler is unable to be uninstalled properly, so these tests are currently disabled. Investigate the
        # issue and enable these 3 tests.
        # _should_fail_single_config_depends_on_disallowed_multi_config,
        # _should_fail_multi_config_depends_on_disallowed_single_config,
        # _should_fail_multi_config_depends_on_disallowed_no_config,
        _should_succeed_single_config_depends_on_single_config,
        _should_succeed_single_config_depends_on_no_config
    ]

    @staticmethod
    def _create_policy_file(ssh_client, policy):
        # Generate a unique file name to avoid conflicts with any other tests running in parallel.
        unique_id = uuid.uuid4()
        file_path = "/tmp/waagent_policy_{0}.json".format(unique_id)
        with open(file_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            policy_file_final_dest = "/etc/waagent_policy.json"
            ssh_client.run_command(f"mv {remote_path} {policy_file_final_dest}", use_sudo=True)
        os.remove(file_path)

    def run(self):

        instances_ip_address: List[VmssInstanceIpAddress] = self._context.vmss.get_instances_ip_address()
        ssh_clients: Dict[str, SshClient] = {}
        for instance in instances_ip_address:
            ssh_clients[instance.instance_name] = SshClient(ip_address=instance.ip_address,
                                                            username=self._context.username,
                                                            identity_file=self._context.identity_file)

        try:
            # Cleanup any extensions left behind by other tests, as they may be blocked by policy and erroneously cause failures.
            instance_view_ext = self._context.vmss.get_instance_view().extensions
            if instance_view_ext is not None and len(instance_view_ext) > 0:
                for ex in instance_view_ext:
                    self._context.vmss.delete_extension(ex.name)

            # Enable policy via conf file.
            for ssh_client in ssh_clients.values():
                ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)

            if not VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(next(iter(ssh_clients.values())).run_command("get_distro.py").rstrip()):
                raise TestSkipped("Currently AzureMonitorLinuxAgent is not supported on this distro")

            # This is the base ARM template that's used for deploying extensions for this scenario.
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
                log.info("")
                log.info("*** Test case: {0}".format(case.__name__.replace('_', ' ')))
                test_case_start = random.choice(list(ssh_clients.values())).run_command("date --utc '+%Y-%m-%d %T'").rstrip()
                if self._scenario_start == datetime_min_utc:
                    self._scenario_start = test_case_start
                log.info("Test case start time: {0}".format(test_case_start))

                # Assign unique guid to forceUpdateTag for each extension to make sure they're always unique to force CRP
                # to generate a new sequence number each time
                test_guid = str(uuid.uuid4())
                policy, extensions, expected_errors, deletion_order = case()
                for ext in extensions:
                    ext["properties"].update({
                        "forceUpdateTag": test_guid
                    })

                # We update the extension template here with extensions that are specific to the scenario that we want to
                # test out
                ext_template = copy.deepcopy(base_extension_template)
                ext_template['resources'][0]['properties']['virtualMachineProfile']['extensionProfile'][
                    'extensions'] = extensions

                # Log the dependencies for the extensions in this test case
                for ext in extensions:
                    provisioned_after = ext['properties'].get('provisionAfterExtensions')
                    depends_on = provisioned_after if provisioned_after else []
                    if depends_on:
                        dependency_list = ' and '.join(depends_on)
                        log.info("{0} depends on {1}".format(ext['name'], dependency_list))
                    else:
                        log.info("{0} does not depend on any extension".format(ext['name']))

                # Copy policy file to each VM instance
                log.info("Updating policy file with new policy: {0}".format(policy))
                for ssh_client in ssh_clients.values():
                    self._create_policy_file(ssh_client, policy)

                log.info("Deploying extensions to the scale set...")
                rg_client = ResourceGroupClient(self._context.vmss.cloud, self._context.vmss.subscription,
                                                self._context.vmss.resource_group, self._context.vmss.location)

                # Deploy updated extension template to the scale set.
                # If test case is supposed to fail, assert that the operation fails with the expected error messages.
                try:
                    rg_client.deploy_template(template=ext_template)
                    if expected_errors is not None and len(expected_errors) != 0:
                        fail("Extension deployment was expected to fail with the following errors: {0}".format(expected_errors))
                    log.info("Extension deployment succeeded as expected")
                    log.info("")
                except Exception as e:
                    if expected_errors is None or len(expected_errors) == 0:
                        fail("Extension template deployment unexpectedly failed: {0}".format(e))
                    else:
                        deployment_failure_pattern = r"[\s\S]*\"code\":\s*\"ResourceDeploymentFailure\"[\s\S]*\"details\":\s*\[\s*(?P<error>[\s\S]*)\]"
                        deployment_failure_match = re.match(deployment_failure_pattern, str(e))
                        try:
                            if deployment_failure_match is None:
                                raise Exception("Unable to match a ResourceDeploymentFailure")
                            error_json = json.loads(deployment_failure_match.group("error"))
                            error_message = error_json['message']
                        except Exception as parse_exc:
                            fail("Extension template deployment failed as expected, but there was an error in parsing the failure. Parsing failure: {0}\nDeployment Failure: {1}".format(parse_exc, e))

                        for phrase in expected_errors:
                            if phrase not in error_message:
                                fail("Extension template deployment failed as expected, but with an unexpected error. Error expected to contain message '{0}'. Actual error: {1}".format(phrase, e))

                    log.info("Extensions failed as expected.")
                    log.info("")
                    log.info("Expected errors:")
                    for expected_error in expected_errors:
                        log.info(" - {0}".format(expected_error))
                    log.info("")
                    log.info("")
                    log.info("Actual errors:")
                    log.info(str(e))

                # Clean up failed extensions to leave VMSS in a good state for the next test. CRP will attempt to uninstall
                # leftover extensions in the next test, but uninstall will be disallowed and reach timeout unexpectedly.
                # CRP also won't allow deletion of an extension that is dependent on another failed extension, so we first
                # update policy to allow all, re-enable all extensions, and then delete them in dependency order.
                log.info("Starting cleanup for test case...")
                allow_all_policy = \
                    {
                        "policyVersion": "0.1.0",
                        "extensionPolicies": {
                            "allowListedExtensionsOnly": False
                        }
                    }
                for ssh_client in ssh_clients.values():
                    self._create_policy_file(ssh_client, allow_all_policy)

                log.info("Trying to re-enable before deleting extensions...")
                for ext in extensions:
                    ext["properties"].update({
                        "forceUpdateTag": str(uuid.uuid4())
                    })
                ext_template['resources'][0]['properties']['virtualMachineProfile']['extensionProfile'][
                    'extensions'] = extensions
                enable_start_time = random.choice(list(ssh_clients.values())).run_command("date --utc '+%Y-%m-%d %T'").rstrip()
                try:
                    rg_client.deploy_template(template=ext_template)
                except Exception as err:
                    # Known issue - CRP returns a stale status for no-config extensions, because it does not wait for a new
                    # sequence number. Only for cases testing no-config extension dependencies, swallow the CRP error and
                    # check agent log instead to confirm that extensions were enabled successfully.
                    test_cases_to_work_around = [
                        _should_fail_single_config_depends_on_disallowed_no_config
                    ]
                    if case in test_cases_to_work_around:
                        log.info("CRP returned error when re-enabling extensions after allowing. Checking agent log to see if enable succeeded. "
                                 "Error: {0}".format(err))
                        time.sleep(2 * 60)  # Give extensions some time to finish processing.
                        extension_list = ' '.join([str(e) for e in deletion_order])
                        command = (f"agent_ext_policy-verify_operation_success.py --after-timestamp '{enable_start_time}' "
                                   f"--operation 'enable' --extension-list {extension_list}")
                        for ssh_client in ssh_clients.values():
                            ssh_client.run_command(command, use_sudo=True)
                        log.info("Agent reported successful status for all extensions, enable succeeded.")
                    else:
                        fail("Failed to re-enable extensions after allowing with policy.")

                # Delete all extensions in dependency order.
                for ext_to_delete in deletion_order:
                    ext_name_to_delete = ext_to_delete.type
                    try:
                        self._context.vmss.delete_extension(ext_name_to_delete)
                    except Exception as crp_err:
                        fail("Failed to uninstall extension {0}. Exception: {1}".format(ext_name_to_delete, crp_err))
                    log.info("Successfully uninstalled extension {0}".format(ext_name_to_delete))

                log.info("Successfully removed all extensions from VMSS")
                log.info("---------------------------------------------")

        finally:
            # Disable policy via conf file and delete policy file.
            for ssh_client in ssh_clients.values():
                ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
                ssh_client.run_command("rm -f /etc/waagent_policy.json", use_sudo=True)
                log.info("")
                log.info("Successfully disabled policy via config (Debug.EnableExtensionPolicy=n) and removed policy file at /etc/waagent_policy.json")

    def get_ignore_errors_before_timestamp(self) -> datetime:
        # Ignore errors in the agent log before the first test case starts
        if self._scenario_start == datetime_min_utc:
            return self._scenario_start
        return datetime.strptime(self._scenario_start, u'%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)

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
            # We intentionally disallow some extensions to test that dependent are skipped. We assert the specific expected failure message in the test.
            #
            {
                'message': r"Dependent extension .* failed or timed out, will skip processing the rest of the extensions"
            },
            #
            # 2023-10-31T17:48:13.349214Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Extensions.CustomScript, op=ExtensionProcessing, message=Dependent Extension Microsoft.Azure.Extensions.CustomScript did not succeed. Status was error, duration=0
            # We intentionally fail to test that dependent extensions are skipped
            #
            {
                'message': r"message=Dependent Extension .* did not succeed. Status was error, duration=0"
            },
            #
            # 2023-10-31T17:47:07.689083Z WARNING ExtHandler ExtHandler [PERIODIC] This status is being reported by the Guest Agent since no status file was reported by extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent: [ExtensionStatusError] Status file /var/lib/waagent/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.28.11/status/6.status does not exist
            # We expect extensions that are dependent on a failing extension to not report status
            #
            {
                'message': r"\[PERIODIC\] This status is being reported by the Guest Agent since no status file was reported by extension .*: \[ExtensionStatusError\] Status file \/var\/lib\/waagent\/.*\/status\/\d+.status does not exist"
            },
            #
            # 2023-10-31T17:48:11.306835Z WARNING ExtHandler ExtHandler A new goal state was received, but not all the extensions in the previous goal state have completed: [('Microsoft.Azure.Extensions.CustomScript', 'error'), ('Microsoft.Azure.Monitor.AzureMonitorLinuxAgent', 'transitioning'), ('Microsoft.CPlat.Core.RunCommandLinux', 'success')]
            # This message appears when the previous test scenario had failing extensions due to extension dependencies
            #
            {
                'message': r"A new goal state was received, but not all the extensions in the previous goal state have completed: \[(\(u?'.*', u?'(error|transitioning|success)'\),?)+\]"
            },
            # 2024-10-23T18:01:32.247341Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=ExtensionProcessing, message=Skipping processing of extensions since execution of dependent extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent failed, duration=0
            # We intentionally block extensions with policy and expect any dependent extensions to be skipped
            {
                'message': r"Skipping processing of extensions since execution of dependent extension .* failed"
            },
            # 2024-10-24T17:34:20.808235Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=None, message=Extension will not be processed: failed to enable extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because extension is not specified in allowlist. To enable, add extension to the allowed list in the policy file ('/etc/waagent_policy.json')., duration=0
            # We intentionally block extensions with policy and expect this failure message
            {
                'message': r"Extension will not be processed"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtPolicyWithDependencies.run_from_command_line()