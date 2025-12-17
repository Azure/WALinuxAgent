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
            # Always send empty protected settings to CSE
            if extension_case.extension.extension_id == VmExtensionIds.CustomScript:
                args["protected_settings"] = {}

        # Add timeout only if specified, else use default
        if timeout is not None:
            args["timeout"] = timeout

        extension_case.extension.enable(**args)

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
            # This solution may run into issues (the following issues are known, but there are likely others):
            #   - while CRP is waiting for the delete operation to timeout, enable requests on the extension will fail, only
            #     delete can be retried.
            #   - if a second delete operation is requested while the first is still running, CRP will merge the goal states
            #     and not send a new goal state to the agent.
            #   - if an enable request is sent while a delete operation is still in progress, the SDK may occasionally throw a
            #     "ResourceNotFound" error
            #
            # Use the following steps as a workaround:
            #   1. asynchronously check the agent log to confirm delete failure
            #   2. force a new goal state by enabling a different extension
            #   3. allow extension with policy and send another delete request (should succeed)
            log.info(f"Attempting to delete {extension_case.extension}, should fail due to policy.")
            delete_start_time = self._ssh_client.run_command("date --utc '+%Y-%m-%d %T'").rstrip()
            try:
                # Wait long enough for CRP timeout (15 min) and confirm that a timeout error was thrown.
                timeout = (20 * 60)
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

        try:
            log.info("*** Begin test setup")

            #  We expect "delete" operations on disallowed VMs to reach timeout, because delete is a best effort operation
            #  by-design and should not fail. For efficiency, we reduce the timeout limit to the minimum allowed (15 minutes).
            log.info("Update CRP timeout period to 15 minutes.")
            self._context.vm.update({"extensionsTimeBudget": "PT15M"})

            # Prepare no-config, single-config, and multi-config extension to test. Extensions with settings and extensions
            # without settings have different status reporting logic, so we should test all cases.
            # CustomScript is a single-config extension.
            custom_script = ExtPolicy.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript),
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
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent),
                None
            )

            # AzureSecurityLinuxAgent is an extension that reports heartbeat.
            azure_security = ExtPolicy.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.AzureSecurityLinuxAgent),
                {}
            )

            # An earlier test suite may have left behind extensions; cleanup any leftovers to test a "fresh" installation
            # for each extension in this suite.
            log.info("")
            log.info("Cleaning up existing extensions on the test VM [%s]", self._context.vm.name)

            # Get the names of extensions currently installed on the VM
            extensions_on_vm = self._context.vm.get_extensions().value
            extension_names_on_vm = {ext.name for ext in extensions_on_vm}

            # Delete any extensions that we want to clean up before testing
            extensions_to_cleanup = [custom_script, run_command, run_command_2, azure_monitor]
            for ext in extensions_to_cleanup:
                if ext.extension._resource_name in extension_names_on_vm:
                    ext.extension.delete()

            # Enable policy via conf file
            log.info("")
            log.info("Enabling policy via conf file on the test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)

            # Azure Policy automatically installs the GuestConfig extension on test machines, which may occur while CRP
            # is waiting for a disallowed delete request to time out (test case 5). In this case, the GuestConfig enable
            # request would be merged with the delete request into a new goal state. CRP would report success for GuestConfig
            # enable, but continue to poll for delete for another full timeout period (15 minutes), extending the total
            # test runtime. As a workaround, we manually install GuestConfig if not already present. If GuestConfig
            # does not support the distro, skip this workaround and the test case (5).
            distro = self._ssh_client.run_command("get_distro.py").rstrip()
            if VmExtensionIds.GuestConfig.supports_distro(distro):
                # Refresh the list of installed extensions and check if GuestConfig is already present
                extension_types_on_vm = {ext.type_properties_type for ext in self._context.vm.get_extensions().value}
                if "ConfigurationforLinux" not in extension_types_on_vm:
                    log.info("")
                    log.info("Installing GuestConfig extension.")
                    guest_config = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.GuestConfig)
                    guest_config.enable(auto_upgrade_minor_version=True)

            log.info("")
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
            if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
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
            if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
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
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                        }
                    }
                }
            self._create_policy_file(policy)
            self._operation_should_fail("enable", custom_script)

            # This policy tests the following scenarios:
            # - allow and enable an extension that reports heartbeat (AzureSecurityLinuxAgent) -> should succeed"
            # - allow a previously-disallowed single-config extension (CustomScript), then enable again -> should succeed
            log.info("")
            log.info("*** Begin test case 4")
            log.info("This policy tests the following scenario:")
            log.info(" - allow and enable an extension that reports heartbeat (AzureSecurityLinuxAgent) -> should succeed")
            log.info(" - allow a previously-disallowed single-config extension (CustomScript), then enable again -> should succeed")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "extensions": {
                            "Microsoft.Azure.Extensions.CustomScript": {},
                            "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent": {},
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                        }
                    }
                }
            self._create_policy_file(policy)
            if VmExtensionIds.AzureSecurityLinuxAgent.supports_distro(distro):
                self._operation_should_succeed("enable", azure_security)
            self._operation_should_succeed("enable", custom_script)

            # This policy tests the following scenarios:
            # - disallow a previously-enabled extension that reports heartbeat (AzureSecurityLinuxAgent), then try to enable again -> should fail
            # - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should reach timeout
            log.info("")
            log.info("*** Begin test case 5")
            log.info("This policy tests the following scenarios:")
            log.info(" - disallow a previously-enabled extension that reports heartbeat (AzureSecurityLinuxAgent), then try to enable again -> should fail")
            log.info(" - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should reach timeout")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                        }
                    }
                }
            self._create_policy_file(policy)
            if VmExtensionIds.AzureSecurityLinuxAgent.supports_distro(distro):
                self._operation_should_fail("enable", azure_security)

            # To avoid Azure Policy automatically installing GuestConfig and extending the timeout period, we manually
            # install it ahead of time on supported distros. However, Azure Policy will still attempt to install GuestConfig on
            # unsupported distros and extend test runtime, so we skip this test case on any unsupported distros.
            if not VmExtensionIds.GuestConfig.supports_distro(distro):
                log.info("Skipping delete failure test case: GuestConfig does not support distro '{0}' but Azure Policy "
                         "may still attempt to install it, extending the timeout period".format(distro))
            else:
                # Because this request marks CSE for deletion, the next operation must be a delete retry (enable will fail).
                self._operation_should_fail("delete", custom_script)

            # This policy tests the following scenarios:
            # - allow a previously-disallowed single-config extension (CustomScript), then try to delete again -> should succeed
            log.info("")
            log.info("*** Begin test case 6")
            log.info("This policy tests the following scenarios:")
            log.info("- allow a previously-disallowed single-config extension (CustomScript), then retry delete -> should succeed")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "extensions": {
                            "Microsoft.Azure.Extensions.CustomScript": {},
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                        }
                    }
                }
            self._create_policy_file(policy)
            self._operation_should_succeed("delete", custom_script)

            # Attempt to delete an extension that was previously blocked (failed to install) -> should succeed.
            # Even if the extension is still disallowed by policy, uninstall should succeed because the extension
            # was never actually installed and no extension code will be executed.
            log.info("")
            log.info("*** Begin test case 7")
            log.info("This policy tests the following scenario: ")
            log.info("- delete a disallowed single-config extension (CustomScript) that previously failed to install due to policy -> should succeed")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": True,
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                        }
                    }
                }
            self._create_policy_file(policy)
            self._operation_should_fail("enable", custom_script)        # CSE should not be installed
            self._operation_should_succeed("delete", custom_script)     # Since CSE was not installed, delete should succeed

        finally:
            # Cleanup after test: disable policy enforcement via conf and delete policy file
            log.info("")
            log.info("*** Begin test cleanup")
            self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
            self._ssh_client.run_command("rm -f /etc/waagent_policy.json", use_sudo=True)
            log.info("Successfully disabled policy via config (Debug.EnableExtensionPolicy=n) and removed policy file at /etc/waagent_policy.json")
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
