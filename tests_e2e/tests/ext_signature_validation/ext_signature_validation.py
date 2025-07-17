#!/usr/bin/env pypy3

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
import re
import uuid
import json
import os
from assertpy import assert_that, fail
from typing import List, Dict, Any


from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier, VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.virtual_machine_runcommand_client import VirtualMachineRunCommandClient
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient


class ExtSignatureValidation(AgentVmTest):
    class _TestCase:
        def __init__(self, extension, settings: Any, protected_settings: Any = None):
            self.extension = extension
            self.settings = settings
            self.protected_settings = protected_settings

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

    def _should_enable_extension(self, extension_case, should_validate_signature):
        """
        Enable extension, and assert that extension is present in instance view.
        If 'should_validate_signature' is true, check that log indicates successful signature and manifest validation,
        and that the validation state is saved.
        """
        log.info("")
        log.info(f"Enabling extension {extension_case.extension}, should succeed")
        enable_start_time = self._ssh_client.run_command("date -u +'%Y-%m-%dT%H:%M:%SZ'").rstrip()

        # Currently, VirtualMachineRunCommandClient does not support restricting RunCommandHandler to a specific version,
        # and therefore, does not support the 'auto_upgrade_minor_version' parameter.
        if not isinstance(extension_case.extension, VirtualMachineRunCommandClient):
            extension_case.extension.enable(settings=extension_case.settings, auto_upgrade_minor_version=False, force_update=True)
        else:
            extension_case.extension.enable(settings=extension_case.settings)
        extension_case.extension.assert_instance_view()
        log.info("")

        if should_validate_signature:
            # Check that signature and manifest were successfully validated, and that state file was created.
            log.info("Check that signature and manifest were successfully validated in agent log, and that state file was created.")
            self._ssh_client.run_command(
                f"ext_signature_validation-check_signature_validated.py "
                f"--extension-name '{extension_case.extension._identifier.type}' --after_timestamp {enable_start_time}",
                use_sudo=True
            )
        log.info(f"Enable succeeded for {extension_case.extension} as expected")

    @staticmethod
    def _should_fail_to_enable_extension(extension_case):
        """
        Extension 'enable' should fail.
        """
        try:
            log.info("")
            log.info(f"Attempting to enable {extension_case.extension} - should fail fast because policy requires signature, but extension is unsigned")
            timeout = (6 * 60)  # Fail fast.
            if not isinstance(extension_case.extension, VirtualMachineRunCommandClient):
                extension_case.extension.enable(settings=extension_case.settings, timeout=timeout, auto_upgrade_minor_version=False, force_update=True)
            else:
                extension_case.extension.enable(settings=extension_case.settings, timeout=timeout)
            fail(f"The agent should have reported an error trying to enable {extension_case.extension} because the extension is unsigned and policy requires signature.")

        except Exception as error:
            # We exclude the extension name from regex because CRP sometimes installs test extensions with different
            # names (ex: Microsoft.Azure.Extensions.Edp.RunCommandHandlerLinuxTest instead of Microsoft.CPlat.Core.RunCommandHandlerLinux)
            pattern = r".*Extension will not be processed: failed to run extension .* because policy specifies that extension must be signed, but extension package signature could not be found.*"
            assert_that(re.search(pattern, str(error))) \
                .described_as(
                f"Error message is expected to contain '{pattern}', but actual error message was '{error}'").is_not_none()
            log.info(f"{extension_case.extension} enable failed as expected due to signature policy")

    def _should_uninstall_extension(self, extension_case):
        log.info("")
        log.info(f"Deleting extension {extension_case.extension}, should succeed")
        extension_case.extension.delete()
        instance_view_extensions = self._context.vm.get_instance_view().extensions
        if instance_view_extensions is not None and any(e.name == extension_case.extension._resource_name for e in instance_view_extensions):
            raise Exception(f"extension {extension_case.extension} still in instance view after attempting to delete")
        log.info(f"Delete succeeded for {extension_case.extension} as expected")


    def _should_fail_to_uninstall_extension(self, extension_case):
        # For delete operations, CRP polls until the agent stops reporting status for the extension, or until timeout is
        # reached, because delete is a best-effort operation and is not expected to fail. However, when delete is called
        # on a disallowed extension, the agent reports failure status, so CRP will continue to poll until timeout.
        # We asynchronously check the instance view and agent log to confirm that deletion failed, and do not wait for CRP timeout.
        #
        # Note: Attempting to enable or retry delete during the CRP polling period may cause issues. Currently, no operations
        # are performed after the failed uninstall test. If this changes in the future, the test should wait for CRP timeout before proceeding.
        log.info(f"Attempting to delete {extension_case.extension}, should fail due to policy.")
        delete_start_time = self._ssh_client.run_command("date -u +'%Y-%m-%dT%H:%M:%SZ'").rstrip()
        try:
            # Allow agent some time to process goal state, but do not wait for full timeout.
            timeout = (3 * 60)
            extension_case.extension.delete(timeout=timeout)
            fail(f"CRP should not have successfully completed the delete operation for {extension_case.extension} "
                 f"because unsigned extensions are disallowed by policy. The agent should have reported a policy failure.")

        except TimeoutError:
            log.info("Delete operation did not complete, as expected. Checking instance view and agent log to confirm that delete operation failed due to signature policy.")
            # Confirm that extension is still present in instance view
            instance_view_extensions = self._context.vm.get_instance_view().extensions
            if instance_view_extensions is not None and not any(e.name == extension_case.extension._resource_name for e in instance_view_extensions):
                fail(f"Delete operation on unsigned extensions is disallowed and should have failed, but extension {extension_case.extension} is no longer present in the instance view.")

            # Confirm that agent log contains error message that uninstall was blocked due to policy.
            # The script will check for a log message such as "Extension will not be processed: failed to uninstall
            # extension 'Microsoft.Azure.Extensions.CustomScript' because policy specifies that extension must be signed, but extension package signature could not be found."
            log.info("Checking agent log to confirm that delete operation failed due to signature policy.")
            self._ssh_client.run_command(f"ext_signature_validation-check_uninstall_blocked.py --extension-name '{extension_case.extension._identifier}' --after-timestamp '{delete_start_time}'", use_sudo=True)

    def _should_enable_multiple_signed_extensions(self, ext_to_enable):
        def get_ext_template(ext):
            ext_template = {
                "type": "Microsoft.Compute/virtualMachines/extensions",
                "name": f"{self._context.vm.name}/{ext.extension._identifier.type}",
                "location": f"{self._context.vm.location}",
                "apiVersion": "2018-06-01",
                "properties": {
                    "publisher": ext.extension._identifier.publisher,
                    "type": ext.extension._identifier.type,
                    "typeHandlerVersion": ext.extension._identifier.version,
                    "autoUpgradeMinorVersion": True,
                    "settings": ext.settings,
                    "protectedSettings": ext.protected_settings
                }
            }
            return ext_template

        base_template = {
            "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": []
        }
        base_template["resources"] = [get_ext_template(ext) for ext in ext_to_enable]
        rg_client = ResourceGroupClient(self._context.vm.cloud, self._context.vm.subscription,
                                        self._context.vm.resource_group, self._context.vm.location)
        try:
            enable_start_time = self._ssh_client.run_command("date -u +'%Y-%m-%dT%H:%M:%SZ'").rstrip()
            log.info(f"Deploying template: \n{json.dumps(base_template, indent=4)}")
            rg_client.deploy_template(template=base_template)
            for case in ext_to_enable:
                log.info(f"Checking that signature was successfully validated for extension '{case.extension._identifier.type}'.")
                self._ssh_client.run_command(
                    f"ext_signature_validation-check_signature_validated.py --extension-name '{case.extension._identifier.type}' --after_timestamp {enable_start_time}",
                    use_sudo=True
                )
        except Exception as ex:
            fail(f"Extension deployment unexpectedly failed: {ex}")

    def run(self):
        # Setup test
        log.info("*** Begin test setup")
        log.info("")
        log.info(" - Get VM distro")
        distro = self._ssh_client.get_distro()
        log.info("VM distro: '{0}'".format(distro))

        # CustomScript 2.1 is a signed, single-config extension.
        cse_id_21 = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions', ext_type='CustomScript',
                                          version="2.1")
        custom_script_signed = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, cse_id_21, resource_name="CustomScript"),
            {'commandToExecute': f"echo '{str(uuid.uuid4())}'"}
        )

        # CustomScript 2.0 is an unsigned, single-config extension.
        cse_id_20 = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions', ext_type='CustomScript', version="2.0")
        custom_script_unsigned = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, cse_id_20, resource_name="CustomScript"),
            {'commandToExecute': f"echo '{str(uuid.uuid4())}'"}
        )

        # RunCommandHandler 1.3 is a signed, multi-config extension.
        rc_id_1_3 = VmExtensionIdentifier(publisher="Microsoft.CPlat.Core", ext_type="RunCommandHandlerLinux", version="1.3")
        run_command_signed = ExtSignatureValidation._TestCase(
            VirtualMachineRunCommandClient(self._context.vm, rc_id_1_3, resource_name="RunCommandHandler"),
            {'source': f"echo '{str(uuid.uuid4())}'"}
        )

        # VMApplicationManagerLinux is a signed, no-config extension.
        vmapp_id_1_0 = VmExtensionIdentifier(publisher='Microsoft.CPlat.Core', ext_type='VMApplicationManagerLinux',
                                            version='1.0')
        vm_app_signed = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, vmapp_id_1_0, resource_name="VMApplicationManagerLinux"),
            None
        )

        # AzureMonitorLinuxAgent 1.33 is an unsigned, no-config extension.
        ama_id_1_33 = VmExtensionIdentifier(publisher='Microsoft.Azure.Monitor', ext_type='AzureMonitorLinuxAgent', version="1.33")
        azure_monitor_unsigned = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, ama_id_1_33, resource_name="AzureMonitorLinuxAgent"),
            None
        )

        # VmAccess 1.5 (signed, single-config) and ApplicationHealthLinux 2.0 (signed, no-config)
        # are additional extensions used to stress test signature validation by including multiple
        # signed extensions in a single goal state.
        vmaccess_id_1_5 = VmExtensionIdentifier(publisher='Microsoft.OSTCExtensions.Edp', ext_type='VMAccessForLinux', version="1.5")
        vm_access_signed = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, vmaccess_id_1_5, resource_name="VMAccessForLinux"),
            settings = None,
            protected_settings={'username': 'testuser'}
        )
        ahl_id_2_0 = VmExtensionIdentifier(publisher='Microsoft.ManagedServices.Edp', ext_type='ApplicationHealthLinux', version="2.0")
        application_health_signed = ExtSignatureValidation._TestCase(
            VirtualMachineExtensionClient(self._context.vm, ahl_id_2_0, resource_name="ApplicationHealthLinux"),
            None
        )

        # Delete any existing extensions on the VM to ensure a clean test setup.
        # Signature validation occurs only during download, so extensions must be removed
        # beforehand to force a fresh download and trigger validation.
        log.info(" - Clean up existing extensions that we want to test on VM")
        extensions_on_vm = self._context.vm.get_extensions().value
        extension_names_on_vm = {ext.name for ext in extensions_on_vm}
        extensions_to_cleanup = [custom_script_unsigned, run_command_signed, vm_app_signed, azure_monitor_unsigned]
        for ext in extensions_to_cleanup:
            if ext.extension._resource_name in extension_names_on_vm:
                ext.extension.delete()

        # This set of test cases will test behavior when signature is validated, but not enforced (telemetry only).
        # Both signed and unsigned extensions should succeed.
        log.info("")
        log.info("*** Begin test cases for signature validation without enforcement. All operations should succeed.")
        # Test unsigned, single-config extension (CustomScript). Extension should be enabled and uninstalled with no errors.
        log.info("")
        log.info("*** Test case 1: should enable and uninstall unsigned single-config extension (CustomScript 2.0) successfully")
        self._should_enable_extension(custom_script_unsigned, should_validate_signature=False)
        self._should_uninstall_extension(custom_script_unsigned)

        # Test signed, single-config extension (CustomScript). Extension signature should be validated, and extension should be enabled and uninstalled with no errors.
        log.info("")
        log.info("*** Test case 2: should validate signature, enable, and uninstall signed single-config extension (CustomScript 2.1) successfully")
        self._should_enable_extension(custom_script_signed, should_validate_signature=True)
        self._should_uninstall_extension(custom_script_signed)

        # Test signed, multi-config extension (RunCommandHandler). Extension signature should be validated, and extension should be enabled and uninstalled with no errors.
        #
        # Note: Currently, the VirtualMachineRunCommand client does not support restricting RunCommandHandler to a specific unsigned version.
        # Therefore, we only test the signed version of RunCommandHandler for now.
        # TODO: Add tests for the unsigned version once the "ForceRunCommandV2Version" flag is fixed for VirtualMachineRunCommandClient
        log.info("")
        log.info("*** Test case 3: should validate signature, enable, and uninstall signed multi-config extension (RunCommandHandler) successfully")
        self._should_enable_extension(run_command_signed, should_validate_signature=True)
        self._should_uninstall_extension(run_command_signed)

        # Test unsigned, no-config extension (AzureMonitorLinuxAgent). Extension should be enabled and uninstalled with no errors.
        log.info("")
        log.info("*** Test case 4: should enable and uninstall unsigned no-config extension (AzureMonitorLinuxAgent 1.33) successfully")
        if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
            self._should_enable_extension(azure_monitor_unsigned, should_validate_signature=False)
            self._should_uninstall_extension(azure_monitor_unsigned)
        else:
            log.info("Skipping test case because AzureMonitorLinuxAgent is not supported on distro '{0}'".format(distro))

        # Test signed, no-config extension (VMApplicationManagerLinux). Extension signature should be validated, and extension should be enabled and uninstalled with no errors.
        log.info("")
        log.info("*** Test case 5: should validate signature, enable, and uninstall signed no-config extension (VMApplicationManagerLinux) successfully")
        self._should_enable_extension(vm_app_signed, should_validate_signature=True)
        self._should_uninstall_extension(vm_app_signed)

        # TODO: Add test cases for package published with invalid signature and invalid manifest signingInfo, when
        # PIR allows for publication of invalid packages.

        log.info("")
        log.info("*** Test case 6: should enable multiple signed extensions in single goal state")
        ext_to_enable = [custom_script_signed, run_command_signed, vm_access_signed, application_health_signed]
        self._should_enable_multiple_signed_extensions(ext_to_enable)

        # This set of test cases will test behavior when signature is validated AND enforced. Unsigned extensions should fail.
        try:
            log.info("")
            log.info("*** Begin test cases for signature validation with enforcement.")
            log.info(" - Create policy to disallow unsigned extensions")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "signatureRequired": True,
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {
                                "signatureRequired": False
                            }
                        }
                    }
                }
            self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)
            self._create_policy_file(policy)

            # When signature is enforced, unsigned single-config extension (CustomScript) should fail to be enabled.
            log.info("")
            log.info("*** Test case 7: should fail to enable unsigned single-config extension (CustomScript 2.0)")
            ExtSignatureValidation._should_fail_to_enable_extension(custom_script_unsigned)

            # When signature is enforced, unsigned no-config extension (AzureMonitorLinuxAgent) should fail to be enabled.
            log.info("")
            log.info("*** Test case 8: should fail to enable unsigned no-config extension (AzureMonitorLinuxAgent 1.33)")
            if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
                ExtSignatureValidation._should_fail_to_enable_extension(azure_monitor_unsigned)
            else:
                log.info("Skipping test case because AzureMonitorLinuxAgent is not supported on distro '{0}'".format(distro))

            # TODO: Add tests for unsigned multi-config extension once "ForceRunCommandV2Version" flag is fixed for VirtualMachineRunCommandClient

            # If extension was previously blocked and never installed, uninstall should succeed even if signature was not validated.
            log.info("")
            log.info("*** Test case 9: should successfully uninstall unsigned extensions that were never enabled (CustomScript, AzureMonitorLinuxAgent")
            self._should_uninstall_extension(custom_script_unsigned)
            if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
                self._should_uninstall_extension(azure_monitor_unsigned)

            # Positive case: signed extensions (no-config, single-config, and multi-config) should all be installed successfully
            log.info("")
            log.info("*** Test case 10: should validate signature and successfully install signed single-config (CustomScript 2.1), no-config (VMApplicationManagerLinux) and multi-config (RunCommandHandler) extensions ")
            self._should_enable_extension(custom_script_signed, should_validate_signature=True)
            self._should_enable_extension(vm_app_signed, should_validate_signature=True)
            self._should_enable_extension(run_command_signed, should_validate_signature=True)

            # Positive case: extensions with signatures that were previously validated should all be uninstall successfully
            log.info("")
            log.info("*** Test case 11: should successfully uninstall signed extensions (single-config, no-config, and multi-config) with previously validated signatures")
            self._should_uninstall_extension(custom_script_signed)
            self._should_uninstall_extension(vm_app_signed)
            self._should_uninstall_extension(run_command_signed)

            # If signed extension was installed when signatureRequired=False and signature was successfully validated, it should be successfully re-enabled when "signatureRequired" is updated to True.
            # If unsigned extension was installed when signatureRequired=False, it should fail to be re-enabled when "signatureRequired" is updated to True.
            log.info("")
            log.info("*** Test case 12: if 'signatureRequired' is updated from False to True, previously validated signed extension (RunCommandHandler) should be re-enabled, unsigned extension (CustomScript) should fail.")
            log.info(" - Set policy to allow unsigned extensions")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "signatureRequired": False
                    }
                }
            self._create_policy_file(policy)
            log.info(" - Install unsigned extension (CustomScript)")
            self._should_enable_extension(custom_script_unsigned, should_validate_signature=False)
            log.info(" - Install signed extension (RunCommandHandler)")
            self._should_enable_extension(run_command_signed, should_validate_signature=True)
            log.info(" - Update policy to disallow unsigned extensions")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "signatureRequired": True,
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {
                                "signatureRequired": False
                            }
                        }
                    }
                }
            self._create_policy_file(policy)
            log.info(" - Re-enable previously validated signed extension (RunCommandHandler), should succeed")
            # Update settings to force a change to the sequence number
            run_command_signed.settings = {'source': f"echo '{str(uuid.uuid4())}'"}
            log.info(" - Re-enable unsigned extension (RunCommandHandler), should fail")
            self._should_fail_to_enable_extension(custom_script_unsigned)
            self._should_enable_extension(run_command_signed, should_validate_signature=False)

            # If an unsigned extension was installed when "signatureRequired=False"

            log.info("")
            log.info("*** Test case 13: should fail to uninstall previously enabled unsigned single-config (CustomScript 2.1) extension")
            log.info(" - Set policy to allow unsigned extensions")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "signatureRequired": False
                    }
                }
            self._create_policy_file(policy)
            log.info(" - Enable unsigned extension, should succeed")
            self._should_enable_extension(custom_script_unsigned, should_validate_signature=False)
            log.info(" - Update policy to disallow unsigned extensions")
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "signatureRequired": True,
                        "extensions": {
                            # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                            "Microsoft.GuestConfiguration.ConfigurationforLinux": {
                                "signatureRequired": False
                            }
                        }
                    }
                }
            self._create_policy_file(policy)
            log.info(" - Try to uninstall unsigned extension, should fail")
            self._should_fail_to_uninstall_extension(custom_script_unsigned)

        finally:
            # Disable policy enforcement via conf and delete policy file
            log.info("")
            log.info("*** Begin test cleanup")
            self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=n", use_sudo=True)
            self._ssh_client.run_command("rm -f /etc/waagent_policy.json", use_sudo=True)
            log.info(
                "Successfully disabled policy via config (Debug.EnableExtensionPolicy=n) and removed policy file at /etc/waagent_policy.json")
            log.info("*** Test cleanup complete.")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            # 2025-05-11T20:00:12.310328Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Extensions.CustomScript, op=ExtensionPolicy, message=Extension will not be processed: failed to run extension 'Microsoft.Azure.Extensions.CustomScript' because policy specifies that extension must be signed, but extension package signature could not be found. To run, set 'signatureRequired' to false in the policy file ('/etc/waagent_policy.json')., duration=0
            # We intentionally block unsigned extensions with policy and expect this failure message
            {
                'message': r"Extension will not be processed: failed to .* extension .* because policy specifies that extension must be signed"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    ExtSignatureValidation.run_from_command_line()
