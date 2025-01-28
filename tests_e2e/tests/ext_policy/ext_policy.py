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
import logging
import json
import re
import uuid
import os
import time
from datetime import datetime, timedelta
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

        # TODO: this logger is for debugging Azure SDK errors, remove after debugging intermittent test failures.
        self._sdk_logger = logging.getLogger('azure')

    def _create_policy_file(self, policy):
        """
        Create policy json file and copy to /etc/waagent_policy.json on test machine.
        """
        unique_id = uuid.uuid4()
        file_path = "/tmp/waagent_policy_{0}.json".format(unique_id)
        with open(file_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            log.info("Policy file contents: {0}".format(json.dumps(policy, indent=4)))

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            policy_file_final_dest = "/etc/waagent_policy.json"
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {policy_file_final_dest}", use_sudo=True)
        os.remove(file_path)

    @staticmethod
    def __retry_operation(operation, max_duration_minutes=15, retry_on_error="ResourceNotFound"):
        """
        Retry the given operation until it succeeds or the timeout is reached. Only retry if the message specified
        by retry_on_error is present in the error.
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=max_duration_minutes)
        last_exc = None
        while datetime.now() < end_time:
            try:
                return operation()
            except Exception as e:
                last_exc = e
                if retry_on_error in str(e):  # Retry only for specified error
                    log.info(f"Error: {e}. Retrying...")
                    time.sleep(30)
                else:
                    raise e
        raise Exception(f"Enable operation failed after retrying for {max_duration_minutes} minutes. Error: {last_exc}")

    @staticmethod
    def __enable_extension(extension_case):
        """
        Temporary helper function to retry "enable" operation, while intermittent failures are investigated.
        TODO: remove retry logic after the issue is resolved

        The Azure SDK/ARM occasionally returns a 'ResourceNotFound' error for an "enable" operation,
        even though the operation succeeds at the agent/CRP level. This issue is observed when enable is called
        immediately after retrying a blocked delete operation. For example:
            1. Block CSE with policy -> delete CSE (fails)
            2. Allow CSE with policy -> delete CSE (succeeds)
            3. Enable CSE -> ARM returns ResourceNotFound error, but operation succeeds in agent

            Error details:
            (ResourceNotFound) The Resource 'Microsoft.Compute/virtualMachines/lisa-WALinuxAgent-20250124-090654-780-e56-n0/extensions/CustomScript' under resource group 'lisa-WALinuxAgent-20250124-090654-780-e56' was not found. For more details please go to https://aka.ms/ARMResourceNotFoundFix
            Code: ResourceNotFound
            Message: The Resource 'Microsoft.Compute/virtualMachines/lisa-WALinuxAgent-20250124-090654-780-e56-n0/extensions/CustomScript' under resource group 'lisa-WALinuxAgent-20250124-090654-780-e56' was not found. For more details please go to https://aka.ms/ARMResourceNotFoundFix!

        To debug this issue, the "enable" operation is retried until it succeeds or a 15-minute timeout is reached, and
        debug logs from the SDK are recorded for further investigation.
        """
        def operation():
            if isinstance(extension_case.extension, VirtualMachineRunCommandClient):
                extension_case.extension.enable(settings=extension_case.settings)
            else:
                extension_case.extension.enable(settings=extension_case.settings, force_update=True)
            extension_case.extension.assert_instance_view()
            raise Exception("ResourceNotFound")

        ExtPolicy.__retry_operation(operation)

    def _operation_should_succeed(self, operation, extension_case):
        log.info("")
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, expected to succeed")
        # Attempt operation. If enabling, assert that the extension is present in instance view.
        # If deleting, assert that the extension is not present in instance view.
        try:
            if operation == "enable":
                ExtPolicy.__enable_extension(extension_case)
            elif operation == "delete":
                extension_case.extension.delete()
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    raise Exception(
                        "extension {0} still in instance view after attempting to delete".format(extension_case.extension))
            log.info(f"Operation '{operation}' for {extension_case.extension.__str__()} succeeded as expected.")
        except Exception as error:
            self._fail_test(
                f"Unexpected error while trying to {operation} {extension_case.extension.__str__()}. "
                f"Extension is allowed by policy so this operation should have completed successfully.\n"
                f"Error: {error}")

    def _operation_should_fail(self, operation, extension_case):
        log.info("")
        if operation == "enable":
            try:
                log.info(f"Attempting to enable {extension_case.extension}, should fail fast due to policy.")
                timeout = (6 * 60)  # Fail fast.
                # VirtualMachineRunCommandClient (and VirtualMachineRunCommand) does not take force_update_tag as a parameter.
                if isinstance(extension_case.extension, VirtualMachineRunCommandClient):
                    extension_case.extension.enable(settings=extension_case.settings, timeout=timeout)
                else:
                    extension_case.extension.enable(settings=extension_case.settings, force_update=True,
                                                    timeout=timeout)
                self._fail_test(
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
            # For efficiency, we asynchronously check the instance view and agent log to confirm that deletion failed,
            # and do not wait for a response from CRP.
            #
            # Note: CRP will not allow an 'enable' request until deletion succeeds or times out. The next call must be
            # a delete operation allowed by policy.
            log.info(f"Attempting to delete {extension_case.extension}, should fail due to policy.")
            delete_start_time = self._ssh_client.run_command("date '+%Y-%m-%d %T'").rstrip()
            try:
                timeout = (3 * 60)  # Allow agent some time to process goal state, but do not wait for full timeout.
                extension_case.extension.delete(timeout=timeout)
                self._fail_test(
                    f"CRP should not have successfully completed the delete operation for {extension_case.extension} "
                    f"because the extension is disallowed by policy and agent should have reported a policy failure.")
            except TimeoutError:
                log.info("Delete operation did not complete, as expected. Checking instance view "
                         "and agent log to confirm that delete operation failed due to policy.")
                # Confirm that extension is still present in instance view
                instance_view_extensions = self._context.vm.get_instance_view().extensions
                if instance_view_extensions is not None and not any(
                        e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                    self._fail_test(
                        f"Delete operation is disallowed by policy and should have failed, but extension "
                        f"{extension_case.extension} is no longer present in the instance view.")

                # Confirm that agent log contains error message that uninstall was blocked due to policy
                # The script will check for a log message such as "Extension will not be processed: failed to uninstall
                # extension 'Microsoft.Azure.Extensions.CustomScript' because it is not specified as an allowed extension"
                self._ssh_client.run_command(
                    f"agent_ext_policy-verify_operation_disallowed.py --extension-name '{extension_case.extension._identifier}' "
                    f"--after-timestamp '{delete_start_time}' --operation 'uninstall'", use_sudo = True)

    def _cleanup_test(self):
        # Disable policy on the test machine and reset logging
        log.info("Stopping Azure SDK debug logging")
        self._sdk_logger.setLevel(logging.INFO)
        self._sdk_logger.removeHandler(log._handler)
        log.info("Disabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)

    def _fail_test(self, message):
        # Wrapper function that cleans up test machine before failing the test.
        # This function should be used instead of fail().
        log.info("Test failed, begin cleanup...")
        self._cleanup_test()
        log.info("Cleanup complete.")
        fail(message)

    def run(self):

        log.info("*** Begin test setup")

        # Direct Azure SDK logging to log file
        self._sdk_logger.addHandler(log._handler)

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


        # This policy tests the following scenarios:
        # - disallow a previously-enabled single-config extension (CustomScript), then try to enable again -> should fail fast
        # - disallow a previously-enabled single-config extension (CustomScript), then try to delete -> should fail fast
        log.info("")
        log.info("*** Begin test case 3")
        log.info("This policy tests the following scenarios:")
        log.info(" - disallow a previously-enabled single-config extension (CustomScript), then try to enable again -> should fail fast")
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
        self._sdk_logger.setLevel(logging.DEBUG)
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

        # Cleanup after test: disable policy enforcement in conf file.
        log.info("")
        log.info("*** Begin test cleanup")
        self._cleanup_test()
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