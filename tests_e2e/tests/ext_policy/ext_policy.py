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
import json
import uuid
from typing import List, Dict, Any
from assertpy import assert_that, fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext


class ExtPolicy(AgentVmTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient, settings: Any):
            self.extension = extension
            self.settings = settings

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def _create_policy_file(self, policy):
        """
        Create policy json file and copy to /etc/waagent_policy.json on test machine.
        """
        with open("waagent_policy.json", mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            policy_file_final_dest = "/etc/waagent_policy.json"
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {policy_file_final_dest}", use_sudo=True)

    def _operation_should_succeed(self, operation, extension_case):
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, expected to succeed ")
        # Attempt operation. If enabling, assert that the extension is present in instance view.
        # If deleting, assert that the extension is not present in instance view.
        try:
            if operation == "enable":
                extension_case.extension.enable(settings=extension_case.settings, force_update=True, timeout=15 * 60)
                extension_case.extension.assert_instance_view()
            elif operation == "delete":
                extension_case.extension.delete(timeout=15 * 60)
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    raise Exception(
                        "extension {0} still in instance view after attempting to delete".format(extension_case.extension._resource_nam))
            log.info(f"Operation '{operation}' for {extension_case.extension.__str__()} succeeded as expected.")
        except Exception as error:
            fail(
                f"Unexpected error while trying to {operation} {extension_case.extension.__str__()}. "
                f"Extension is allowed by policy so this operation should have completed successfully.\n"
                f"Error: {error}")

    @staticmethod
    def _operation_should_fail(operation, extension_case):
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, should fail fast.")
        try:
            timeout = (6 * 60)  # Fail fast.
            if operation == "enable":
                extension_case.extension.enable(settings=extension_case.settings, force_update=True, timeout=timeout)
            elif operation == "delete":
                extension_case.extension.delete(timeout=timeout)
            fail(f"The agent should have reported an error trying to {operation} {extension_case.extension.__str__()} "
                 f"because the extension is disallowed by policy.")
        except Exception as error:
            assert_that("Extension is disallowed by agent policy and will not be processed" in str(error)) \
                .described_as(
                f"Error message should communicate that extension is disallowed by policy, but actual error "
                f"was: {error}").is_true()
            log.info(f"{extension_case.extension.__str__()} {operation} failed as expected")

    def run(self):

        # Prepare extensions to test
        unique = str(uuid.uuid4())
        test_file = f"waagent-test.{unique}"
        custom_script = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript,
                                          resource_name="CustomScript"),
            {'commandToExecute': f"echo '{unique}' > /tmp/{test_file}"}
        )
        run_command = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandler"),
            {'source': {'script': f"echo '{unique}' > /tmp/{test_file}"}}
        )
        azure_monitor = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent,
                                          resource_name="AzureMonitorLinuxAgent"),
            None
        )
        unique2 = str(uuid.uuid4())
        test_file2 = f"waagent-test.{unique2}"
        run_command_2 = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandler2"),
            {'source': {'script': f"echo '{unique2}' > /tmp/{test_file2}"}}
        )

        # Enable policy via conf
        log.info("Enabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)

        # Test case 1: should only enable allowlisted extensions
        # CustomScript should be enabled, RunCommand and AzureMonitor should fail.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        "Microsoft.Azure.Extensions.CustomScript": {}
                    }
                }
            }
        self._create_policy_file(policy)
        self._operation_should_succeed("enable", custom_script)
        self._operation_should_fail("enable", run_command)
        if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro((self._ssh_client.run_command("get_distro.py").rstrip())):
            self._operation_should_fail("enable", azure_monitor)

        # Test case 2: turn allowlist off
        # RunCommand should be successfully enabled and then deleted.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": False,
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)
        self._operation_should_succeed("enable", run_command)
        self._operation_should_succeed("delete", run_command)
        if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro((self._ssh_client.run_command("get_distro.py").rstrip())):
            self._operation_should_succeed("enable", azure_monitor)
            self._operation_should_succeed("delete", azure_monitor)

        # Test case 3: uninstall should fail when disallowed
        # Remove CustomScript from allowlist and try to uninstall, should fail.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)

        # Known CRP issue - delete/uninstall operation times out instead of reporting an error.
        # TODO: uncomment this test case after issue is resolved
        # self._operation_should_fail("delete", custom_script)

        # Test case 4: both instances in a multiconfig extension should fail, if disallowed.
        # Disallow RunCommand and try to install two instances, both should fail fast.
        self._operation_should_fail("enable", run_command)
        self._operation_should_fail("enable", run_command_2)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # 2024-10-23T17:50:38.107793Z WARNING ExtHandler ExtHandler Dependent extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent failed or timed out, will skip processing the rest of the extensions
            # We intentionally block extensions with policy and expect any dependent extensions to be skipped
            {
                'message': r"Dependent extension .* failed or timed out, will skip processing the rest of the extensions"
            },
            # 2024-10-23T18:01:32.247341Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=ExtensionProcessing, message=Skipping processing of extensions since execution of dependent extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent failed, duration=0
            # We intentionally block extensions with policy and expect any dependent extensions to be skipped
            {
                'message': r"Skipping processing of extensions since execution of dependent extension .* failed"
            },
            # 2024-10-24T17:34:20.808235Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=None, message=[ExtensionPolicyError] Extension is disallowed by agent policy and will not be processed: failed to enable extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because extension is not specified in allowlist. To enable, add extension to the allowed list in the policy file ('/etc/waagent_policy.json')., duration=0
            # We intentionally block extensions with policy and expect this failure message
            {
                'message': r"Extension is disallowed by agent policy and will not be processed"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtPolicy.run_from_command_line()
