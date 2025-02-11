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
import re
import time
import uuid
import os
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
        unique_id = uuid.uuid4()
        file_path = f"/tmp/waagent_policy_{unique_id}.json"
        with open(file_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            log.info(f"Policy file contents: {json.dumps(policy, indent=4)}")

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            policy_file_final_dest = "/etc/waagent_policy.json"
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {policy_file_final_dest}", use_sudo=True)
        os.remove(file_path)

    @staticmethod
    def __enable_extension(extension_case, timeout=None):
        """Helper to call 'enable' with appropriate parameters."""
        args = {"settings": extension_case.settings}

        # VirtualMachineRunCommandClient (and VirtualMachineRunCommand) does not take force_update_tag as a parameter.
        # For all other extensions, always set force_update to true.
        if not isinstance(extension_case.extension, VirtualMachineRunCommandClient):
            args["force_update"] = True

        # Add timeout only if specified, else use default
        if timeout is not None:
            args["timeout"] = timeout

        extension_case.extension.enable(**args)

    @staticmethod
    def _enable_should_succeed_with_retry(extension_case, retry_on_error, retries=2):
        """
        This method was created to work around an intermittent failure for test case 4. Attempts the 'enable' operation,
        retrying after a short delay if the error message contains the specified string 'retry_on_error'.

        On test case 4,  the Azure SDK/ARM occasionally returns a 'ResourceNotFound' error for the 'enable' operation (#3),
        even though all 3 operations in the test case succeed at the agent and CRP level.
            1. Block CSE with policy -> delete CSE (ARM/CRP continues polling until timeout, test moves to next operation)
            2. Allow CSE with policy -> delete CSE (succeeds)
            3. Enable CSE -> SDK returns ResourceNotFound error
            
            Error details:
            (ResourceNotFound) The Resource 'Microsoft.Compute/virtualMachines/lisa-WALinuxAgent-20250124-090654-780-e56-n0/extensions/CustomScript' under resource group 'lisa-WALinuxAgent-20250124-090654-780-e56' was not found. For more details please go to https://aka.ms/ARMResourceNotFoundFix
            Code: ResourceNotFound
            Message: The Resource 'Microsoft.Compute/virtualMachines/lisa-WALinuxAgent-20250124-090654-780-e56-n0/extensions/CustomScript' under resource group 'lisa-WALinuxAgent-20250124-090654-780-e56' was not found. For more details please go to https://aka.ms/ARMResourceNotFoundFix

        The suspected cause is that ARM receives the enable request (#3) before the second delete operation (#2) has
        completed at the ARM level, leading to a conflict. When the first delete operation (#1) fails, the agent reports
        a failure status for the extension, but CRP continues to wait for the agent to stop reporting status for that
        extension. Once the second delete operation (#2) succeeds, the agent stops reporting status for that extension,
        so ARM reports success for the *first* delete operation and reports that the second delete is still in progress.
        Consequently, the enable request (#3) is accepted by ARM but conflicts with the ongoing delete operation (#2),
        causing the SDK to report a ResourceNotFound error.

        To work around this issue, we retry 'enable' a few times if the string 'ResourceNotFound' is found in the error message.
        If the issue continues after retrying, another possible workaround is to wait for the full CRP timeout for delete #1.
        """
        log.info("")
        log.info(f"Attempting to enable {extension_case.extension}, expected to succeed")
        error = None
        for attempt in range(retries):
            try:
                ExtPolicy.__enable_extension(extension_case)
                extension_case.extension.assert_instance_view()
                log.info(f"Operation 'enable' for {extension_case.extension} succeeded.")
                return

            except Exception as e:
                error = e
                # Only retry if the specified string is found in the error message.
                if retry_on_error in str(e):
                    log.warning(f"Operation 'enable' failed with a {retry_on_error} error on attempt {attempt + 1}, retrying in 30 secs. Error: {e}")
                    time.sleep(30)
                else:
                    fail(
                        f"Unexpected error while trying to enable {extension_case.extension}. "
                        f"Extension is allowed by policy so this operation should have completed successfully.\n"
                        f"Error: {e}")

        fail(f"Enable {extension_case.extension} failed after {retries} retries. Last error: {error}")

    def _operation_should_succeed(self, operation, extension_case):
        log.info("")
        log.info(f"Attempting to {operation} {extension_case.extension}, expected to succeed")
        # Attempt operation. If enabling, assert that the extension is present in instance view.
        # If deleting, assert that the extension is not present in instance view.
        try:
            if operation == "enable":
                ExtPolicy.__enable_extension(extension_case)
                extension_case.extension.assert_instance_view()

            elif operation == "delete":
                extension_case.extension.delete()
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    raise Exception(f"extension {extension_case.extension} still in instance view after attempting to delete")

            log.info(f"Operation '{operation}' for {extension_case.extension} succeeded as expected.")

        except Exception as error:
            fail(
                f"Unexpected error while trying to {operation} {extension_case.extension}. "
                f"Extension is allowed by policy so this operation should have completed successfully.\n"
                f"Error: {error}")

    def _operation_should_fail(self, operation, extension_case):
        log.info("")
        if operation == "enable":
            try:
                log.info(f"Attempting to enable {extension_case.extension}, should fail fast due to policy.")
                timeout = (6 * 60)  # Fail fast.
                ExtPolicy.__enable_extension(extension_case, timeout)
                fail(
                    f"The agent should have reported an error trying to {operation} {extension_case.extension} "
                    f"because the extension is disallowed by policy.")

            except Exception as error:
                # We exclude the extension name from regex because CRP sometimes installs test extensions with different
                # names (ex: Microsoft.Azure.Extensions.Edp.RunCommandHandlerLinuxTest instead of Microsoft.CPlat.Core.RunCommandHandlerLinux)
                pattern = r".*Extension will not be processed: failed to run extension .* because it is not specified as an allowed extension.*"
                assert_that(re.search(pattern, str(error))) \
                    .described_as(
                    f"Error message is expected to contain '{pattern}', but actual error message was '{error}'").is_not_none()
                log.info(f"{extension_case.extension} {operation} failed as expected due to policy")

        elif operation == "delete":
            # For delete operations, CRP polls until the agent stops reporting status for the extension, or until timeout is
            # reached, because delete is a best-effort operation and is not expected to fail. However, when delete is called
            # on a disallowed extension, the agent reports failure status, so CRP will continue to poll until timeout.
            # We wait for the full timeout period (set to 15 minutes), verify that CRP returns a timeout error, and
            # check the agent log to confirm that delete was blocked by policy.
            #
            # Note: this scenario is currently executed only once. If it must be run multiple times in the future,
            # avoid waiting for CRP timeout and asynchronously check agent log to confirm delete failure.
            # This solution may run into some issues:
            #   - while CRP is waiting for the delete operation to timeout, enable requests on the extension will fail, only
            #     delete can be retried.
            #   - if a second delete operation is requested while the first is still running, CRP will merge the goal states
            #     and not send a new goal state to the agent.
            # Use the following steps as a workaround:
            #   1. asynchronously check the agent log to confirm delete failure
            #   2. force a new goal state by enabling a different extension
            #   3. allow extension with policy and send another delete request (should succeed).
            #
            log.info(f"Attempting to delete {extension_case.extension}, should fail due to policy.")
            delete_start_time = self._ssh_client.run_command("date '+%Y-%m-%d %T'").rstrip()
            try:
                # Wait long enough for CRP timeout (15 min) and confirm that a timeout error was thrown.
                timeout = (30 * 60)
                extension_case.extension.delete(timeout=timeout)
                fail(f"CRP should not have successfully completed the delete operation for {extension_case.extension} "
                     f"because the extension is disallowed by policy and agent should have reported a policy failure.")

            except Exception as error:
                assert_that("VMExtensionProvisioningTimeout" in str(error)) \
                    .described_as(f"Expected a VMExtensionProvisioningTimeout error, but actual error was: {error}") \
                    .is_true()
                log.info("Delete operation timed out, as expected. Error:")
                log.info(error)
                log.info("")
                log.info("Checking agent log to confirm that delete operation failed due to policy.")

                # Confirm that agent log contains error message that uninstall was blocked due to policy
                # The script will check for a log message such as "Extension will not be processed: failed to uninstall
                # extension 'Microsoft.Azure.Extensions.CustomScript' because it is not specified as an allowed extension"
                self._ssh_client.run_command(
                    f"agent_ext_policy-verify_operation_disallowed.py --extension-name '{extension_case.extension._identifier}' "
                    f"--after-timestamp '{delete_start_time}' --operation 'uninstall'", use_sudo = True)

    def run(self):

        log.info("*** Begin test setup")

        #  We expect "delete" operations on disallowed VMs to reach timeout, because delete is a best effort operation
        #  by-design and should not fail. For efficiency, we reduce the timeout limit to the minimum allowed (15 minutes).
        log.info("Update CRP timeout period to 15 minutes.")
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
        # We only enable AMA on supported distros.
        # If we were to enable AMA on an unsupported distro, the operation would initially be blocked by policy as
        # expected. However, after changing the policy to allow all with the next goal state, the agent would attempt to
        # re-enable AMA on an unsupported distro, causing errors.
        if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro((self._ssh_client.run_command("get_distro.py").rstrip())):
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
        self._operation_should_succeed("enable", custom_script)
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

        # This policy tests the following scenario:
        # - disallow a previously-enabled single-config extension (CustomScript), then try to enable again -> should fail fast
        log.info("")
        log.info("*** Begin test case 3")
        log.info("This policy tests the following scenario:")
        log.info(" - disallow a previously-enabled single-config extension (CustomScript), then enable again -> should fail fast")
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

        # This policy tests the following scenario:
        # - allow a previously-disallowed single-config extension (CustomScript), then enable again -> should succeed
        log.info("")
        log.info("*** Begin test case 4")
        log.info("This policy tests the following scenario:")
        log.info(" - allow a previously-disallowed single-config extension (CustomScript), then enable again -> should succeed")
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
        self._operation_should_succeed("enable", custom_script)

        # This policy tests the following scenarios:
        # - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should reach timeout
        log.info("")
        log.info("*** Begin test case 5")
        log.info("This policy tests the following scenarios:")
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
        self._operation_should_fail("delete", custom_script)

        # Cleanup after test: disable policy enforcement in conf file.
        log.info("")
        log.info("*** Begin test cleanup")
        log.info("Disabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
        log.info("*** Test cleanup complete.")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # 2024-10-24T17:34:20.808235Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=None, message=[ExtensionPolicyError] Extension will not be processed: failed to run extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because it is not specified as an allowed extension. To enable, add the extension to the list of allowed extensions in the policy file ('/etc/waagent_policy.json')., duration=0
            # We intentionally block extensions with policy and expect this failure message
            {
                'message': r"Extension will not be processed: failed to .* extension .* because it is not specified as an allowed extension"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtPolicy.run_from_command_line()