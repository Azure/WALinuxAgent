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
from tests_e2e.tests.lib.virtual_machine_runcommand_client import VirtualMachineRunCommandClient
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext


class ExtPolicy(AgentVmTest):
    class TestCase:
        def __init__(self, extension, settings: Any):
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
        log.info("")
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, expected to succeed ")
        # Attempt operation. If enabling, assert that the extension is present in instance view.
        # If deleting, assert that the extension is not present in instance view.
        try:
            if operation == "enable":
                # VirtualMachineRunCommandClient (and VirtualMachineRunCommand) does not take force_update_tag as a parameter.
                if isinstance(extension_case.extension, VirtualMachineRunCommandClient):
                    extension_case.extension.enable(settings=extension_case.settings)
                else:
                    extension_case.extension.enable(settings=extension_case.settings, force_update=True)
                extension_case.extension.assert_instance_view()
            elif operation == "delete":
                extension_case.extension.delete()
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    raise Exception(
                        "extension {0} still in instance view after attempting to delete".format(extension_case.extension))
            log.info(f"Operation '{operation}' for {extension_case.extension.__str__()} succeeded as expected.")
        except Exception as error:
            fail(
                f"Unexpected error while trying to {operation} {extension_case.extension.__str__()}. "
                f"Extension is allowed by policy so this operation should have completed successfully.\n"
                f"Error: {error}")

    def _operation_should_fail(self, operation, extension_case):
        log.info("")
        if operation == "enable":
            try:
                log.info(f"Attempting to enable {extension_case.extension}, should fail fast.")
                timeout = (6 * 60)  # Fail fast.
                # VirtualMachineRunCommandClient (and VirtualMachineRunCommand) does not take force_update_tag as a parameter.
                if type(extension_case.extension) == VirtualMachineRunCommandClient:
                    extension_case.extension.enable(settings=extension_case.settings, timeout=timeout)
                else:
                    extension_case.extension.enable(settings=extension_case.settings, force_update=True,
                                                    timeout=timeout)
                fail(
                    f"The agent should have reported an error trying to {operation} {extension_case.extension} "
                    f"because the extension is disallowed by policy.")
            except Exception as error:
                expected_msg = "Extension will not be processed: failed to run extension"
                assert_that(expected_msg in str(error)) \
                    .described_as(
                    f"Error message is expected to contain '{expected_msg}', but actual error message was '{error}'").is_true()
                log.info(f"{extension_case.extension} {operation} failed as expected")

        elif operation == "delete":
            # Delete is a best effort operation and should not fail, so CRP will timeout instead of reporting the
            # appropriate error. We swallow the timeout error, and instead, assert that the extension is still in the
            # instance view and that the expected error is in the agent log to confirm that deletion failed.
            log.info(f"Attempting to delete {extension_case.extension}, should reach timeout.")
            delete_start_time = self._ssh_client.run_command("date '+%Y-%m-%d %T'").rstrip()
            try:
                # TODO: consider checking the agent's log asynchronously to confirm that the uninstall failed instead of
                # waiting for the full CRP timeout.
                extension_case.extension.delete()
                fail(f"CRP should have reported a timeout error when attempting to delete {extension_case.extension} "
                     f"because the extension is disallowed by policy and agent should have reported a policy failure.")
            except TimeoutError:
                log.info("Reported a timeout error when attempting to delete extension, as expected. Checking instance view "
                         "and agent log to confirm that delete operation failed.")
                # Confirm that extension is still present in instance view
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and not any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    fail(f"Delete operation is disallowed by policy and should have failed, but extension "
                         f"{extension_case.extension} is no longer present in the instance view.")

                # Confirm that expected error message is in the agent log
                expected_msg = "Extension will not be processed: failed to uninstall extension"
                self._ssh_client.run_command(
                    f"agent_ext_workflow-check_data_in_agent_log.py --data '{expected_msg}' --after-timestamp '{delete_start_time}'",
                    use_sudo=True)

    def run(self):

        # The full CRP timeout period for extension operation failure is 90 minutes. For efficiency, we reduce the
        # timeout limit to 15 minutes here. We expect "delete" operations on disallowed VMs to reach timeout instead of
        # failing fast, because delete is a best effort operation by-design and should not fail.
        log.info("*** Begin test setup")
        log.info("Set CRP timeout to 15 minutes")
        self._context.vm.update({"extensionsTimeBudget": "PT15M"})

        # Prepare no-config, single-config, and multi-config extension to test. Extensions with settings and extensions
        # without settings have different status reporting logic, so we should test all cases.
        # CustomScript is a single-config extension.
        custom_script = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript,
                                          resource_name="CustomScript"),
            {'commandToExecute': f"echo '{str(uuid.uuid4())}'"}
        )

        # RunCommandHandler is a multi-config extension, so we set up two instances (configurations) here and test both.
        # We append the resource name with "Policy" because agent_bvt/run_command.py leaves behind a "RunCommandHandler"
        # that cannot be deleted via extensions API.
        run_command = ExtPolicy.TestCase(
            VirtualMachineRunCommandClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandlerPolicy"),
            {'source': f"echo '{str(uuid.uuid4())}'"}
        )
        run_command_2 = ExtPolicy.TestCase(
            VirtualMachineRunCommandClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandlerPolicy2"),
            {'source': f"echo '{str(uuid.uuid4())}'"}
        )

        # AzureMonitorLinuxAgent is a no-config extension (extension without settings).
        azure_monitor = ExtPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent,
                                          resource_name="AzureMonitorLinuxAgent"),
            None
        )

        # Another e2e test may have left behind an extension we want to test here. Cleanup any leftovers so that they
        # do not affect the test results.
        log.info("Cleaning up existing extensions on the test VM [%s]", self._context.vm.name)
        # TODO: Consider deleting only extensions used by this test instead of all extensions.
        self._context.vm.delete_all_extensions()

        # Enable policy via conf file
        log.info("Enabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)
        log.info("Test setup complete.")

        # This policy tests the following scenarios:
        # - enable a single-config extension (CustomScript) that is allowed by policy -> should succeed
        # - enable a no-config extension (AzureMonitorLinuxAgent) that is disallowed by policy -> should fail fast
        # - enable two instances of a multi-config extension (RunCommandHandler) that is disallowed by policy -> both should fail fast
        # (Note that CustomScript disallowed by policy is tested in a later test case.)
        log.info("")
        log.info("*** Begin test case 1")
        log.info("This policy tests the following scenarios:")
        log.info(" - enable a single-config extension (CustomScript) that is allowed by policy -> should succeed")
        log.info(" - enable a no-config extension (AzureMonitorLinuxAgent) that is disallowed by policy -> should fail fast")
        log.info(" - enable two instances of a multi-config extension (RunCommandHandler) that is disallowed by policy -> both should fail fast")
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        "Microsoft.Azure.Extensions.CustomScript": {},
                        # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                        "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                    }
                }
            }
        self._create_policy_file(policy)
        self._operation_should_succeed("enable", custom_script)
        self._operation_should_fail("enable", run_command)
        self._operation_should_fail("enable", run_command_2)
        self._operation_should_fail("enable", azure_monitor)

        # This policy tests the following scenarios:
        # - enable two instances of a multi-config extension (RunCommandHandler) when allowed by policy -> should succeed
        # - delete two instances of a multi-config extension (RunCommandHandler) when allowed by policy -> should succeed
        # - enable no-config extension (AzureMonitorLinuxAgent) when allowed by policy -> should succeed
        # - delete no-config extension (AzureMonitorLinuxAgent) when allowed by policy -> should succeed
        log.info("")
        log.info("*** Begin test case 2")
        log.info("This policy tests the following scenarios:")
        log.info(" - enable two instances of a multi-config extension (RunCommandHandler) when allowed by policy -> should succeed")
        log.info(" - delete two instances of a multi-config extension (RunCommandHandler) when allowed by policy -> should succeed")
        log.info(" - enable no-config extension (AzureMonitorLinuxAgent) when allowed by policy -> should succeed")
        log.info(" - delete no-config extension (AzureMonitorLinuxAgent) when allowed by policy -> should succeed")
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
        # Update settings to force an update to the seq no
        run_command.settings = {'source': f"echo '{str(uuid.uuid4())}'"}
        run_command_2.settings = {'source': f"echo '{str(uuid.uuid4())}'"}
        self._operation_should_succeed("enable", run_command)
        self._operation_should_succeed("enable", run_command_2)
        self._operation_should_succeed("delete", run_command)
        self._operation_should_succeed("delete", run_command_2)
        if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro((self._ssh_client.run_command("get_distro.py").rstrip())):
            self._operation_should_succeed("enable", azure_monitor)
            self._operation_should_succeed("delete", azure_monitor)

        # This policy tests the following scenarios:
        # - disallow a previously-enabled single-config extension (CustomScript, then try to enable again -> should fail fast
        # - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should fail fast
        log.info("")
        log.info("*** Begin test case 3")
        log.info("This policy tests the following scenarios:")
        log.info(" - disallow a previously-enabled single-config extension (CustomScript, then try to enable again -> should fail fast")
        log.info(" - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should reach timeout")
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                        "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                    }
                }
            }
        self._create_policy_file(policy)
        self._operation_should_fail("enable", custom_script)
        self._operation_should_fail("delete", custom_script)

        # This policy tests the following scenario:
        # - allow a previously-disallowed single-config extension (CustomScript), then delete -> should succeed
        # - allow a previously-disallowed single-config extension (CustomScript), then enable -> should succeed
        log.info("")
        log.info("*** Begin test case 4")
        log.info("This policy tests the following scenario:")
        log.info(" - allow a previously-disallowed single-config extension (CustomScript), then delete -> should succeed")
        log.info(" - allow a previously-disallowed single-config extension (CustomScript), then enable -> should succeed")
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
        # Since CustomScript is marked for deletion by previous test case, we can only retry the delete operation (enable
        # is not allowed by CRP). So we first delete successfully, and then re-install/enable CustomScript.
        self._operation_should_succeed("delete", custom_script)
        self._operation_should_succeed("enable", custom_script)

        # Cleanup after test: delete leftover extensions and disable policy enforcement in conf file.
        log.info("")
        log.info("*** Begin test cleanup")
        log.info("Disabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
        # TODO: Consider deleting only extensions used by this test instead of all extensions.
        self._context.vm.delete_all_extensions()
        log.info("*** Test cleanup complete.")




    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # 2024-10-24T17:34:20.808235Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=None, message=[ExtensionPolicyError] Extension will not be processed: failed to run extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because it is not specified in the allowlist. To enable, add extension to the allowed list in the policy file ('/etc/waagent_policy.json')., duration=0
            # We intentionally block extensions with policy and expect this failure message
            {
                'message': r"Extension will not be processed: failed to .* extension .* because it is not specified as an allowed extension"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtPolicy.run_from_command_line()
