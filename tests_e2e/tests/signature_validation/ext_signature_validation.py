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
import uuid
from typing import Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier, VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.virtual_machine_runcommand_client import VirtualMachineRunCommandClient
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.ssh_client import SshClient


class ExtSignatureValidation(AgentVmTest):
    class TestCase:
        def __init__(self, extension, settings: Any):
            self.extension = extension
            self.settings = settings

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def _should_enable_extension(self, extension_case, should_validate_signature):
        """
        Enable extension, and assert that extension is present in instance view.
        If 'should_validate_signature' is true, check that log indicates successful signature and manifest validation,
        and that the validation state is saved.
        """
        log.info("")
        log.info(f"Enabling extension {extension_case.extension}, should succeed")
        enable_start_time = self._ssh_client.run_command("date -u +'%Y-%m-%dT%H:%M:%SZ'").rstrip()
        if not isinstance(extension_case.extension, VirtualMachineRunCommandClient):
            extension_case.extension.enable(settings=extension_case.settings, auto_upgrade_minor_version=False)
        else:
            extension_case.extension.enable(settings=extension_case.settings)
        extension_case.extension.assert_instance_view()
        log.info("")

        if should_validate_signature:
            # Confirm that agent logs successful signature validation and handler manifest validation
            log.info("Checking agent log to confirm that package signature was validated successfully.")
            signature_log_msg = "Successfully validated signature for extension"
            self._ssh_client.run_command(f"agent_ext_workflow-check_data_in_agent_log.py --data '{signature_log_msg}' "
                                         f"--after-timestamp '{enable_start_time}'", use_sudo=True)

            log.info("Checking agent log to confirm that handler manifest was validated successfully.")
            manifest_log_msg = "Successfully validated handler manifest"
            self._ssh_client.run_command(f"agent_ext_workflow-check_data_in_agent_log.py --data '{manifest_log_msg}' "
                                         f"--after-timestamp '{enable_start_time}'", use_sudo=True)

            # Check signature validation state
            log.info("Checking that signature validation state file exists.")
            self._ssh_client.run_command(
                f"agent_ext_signature_validation-verify_state.py --extension-name '{extension_case.extension._identifier.type}'",
                use_sudo=True
            )
        log.info(f"Enable succeeded for {extension_case.extension} as expected")

    def _should_uninstall_extension(self, extension_case):
        log.info("")
        log.info(f"Deleting extension {extension_case.extension}, should succeed")
        extension_case.extension.delete()
        instance_view_extensions = self._context.vm.get_instance_view().extensions
        if instance_view_extensions is not None and any(e.name == extension_case.extension._resource_name for e in instance_view_extensions):
            raise Exception(f"extension {extension_case.extension} still in instance view after attempting to delete")
        log.info(f"Delete succeeded for {extension_case.extension} as expected")

    def run(self):
        try:
            # Setup test
            log.info("*** Begin test setup")
            log.info("")
            log.info(" - Get VM distro")
            distro = self._ssh_client.run_command("get_distro.py").rstrip()

            # CustomScript 2.1 is a signed, single-config extension.
            cse_id_21 = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions', ext_type='CustomScript',
                                              version="2.1")
            custom_script_signed = ExtSignatureValidation.TestCase(
                VirtualMachineExtensionClient(self._context.vm, cse_id_21, resource_name="CustomScript"),
                {'commandToExecute': f"echo '{str(uuid.uuid4())}'"}
            )

            # CustomScript 2.0 is an unsigned, single-config extension.
            cse_id_20 = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions', ext_type='CustomScript', version="2.0")
            custom_script_unsigned = ExtSignatureValidation.TestCase(
                VirtualMachineExtensionClient(self._context.vm, cse_id_20, resource_name="CustomScript"),
                {'commandToExecute': f"echo '{str(uuid.uuid4())}'"}
            )

            # RunCommandHandler 1.3 is a signed, multi-config extension.
            rc_id_1_3 = VmExtensionIdentifier(publisher="Microsoft.CPlat.Core", ext_type="RunCommandHandlerLinux", version="1.3")
            run_command_signed = ExtSignatureValidation.TestCase(
                VirtualMachineRunCommandClient(self._context.vm, rc_id_1_3, resource_name="RunCommandHandler"),
                {'source': f"echo '{str(uuid.uuid4())}'"}
            )

            # VMApplicationManagerLinux is a signed, no-config extension.
            vmapp_id_1_0 = VmExtensionIdentifier(publisher='Microsoft.CPlat.Core', ext_type='VMApplicationManagerLinux',
                                                version='1.0')
            vm_app_signed = ExtSignatureValidation.TestCase(
                VirtualMachineExtensionClient(self._context.vm, vmapp_id_1_0, resource_name="VMApplicationManagerLinux"),
                None
            )

            # AzureMonitorLinuxAgent 1.33 is an unsigned, no-config extension.
            ama_id_1_33 = VmExtensionIdentifier(publisher='Microsoft.Azure.Monitor', ext_type='AzureMonitorLinuxAgent', version="1.33")
            azure_monitor_unsigned = ExtSignatureValidation.TestCase(
                VirtualMachineExtensionClient(self._context.vm, ama_id_1_33, resource_name="AzureMonitorLinuxAgent"),
                None
            )

            # Delete any existing extensions on VM that we want to clean up before testing
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
            if VmExtensionIds.AzureMonitorLinuxAgent.supports_distro(distro):
                log.info("")
                log.info("*** Test case 4: should enable and uninstall unsigned no-config extension (AzureMonitorLinuxAgent 1.33) successfully")
                self._should_enable_extension(azure_monitor_unsigned, should_validate_signature=False)
                self._should_uninstall_extension(azure_monitor_unsigned)

            # Test signed, no-config extension (VMApplicationManagerLinux). Extension signature should be validated, and extension should be enabled and uninstalled with no errors.
            log.info("")
            log.info("*** Test case 5: should validate signature, enable, and uninstall signed no-config extension (VMApplicationManagerLinux) successfully")
            self._should_enable_extension(vm_app_signed, should_validate_signature=True)
            self._should_uninstall_extension(vm_app_signed)

            # TODO: Add test cases for package published with invalid signature and invalid manifest signingInfo, when
            # PIR allows for publication of invalid packages.

        finally:
            log.info("")
            log.info("*** Begin test cleanup")
            self._ssh_client.run_command("update-waagent-conf Debug.EnableSignatureValidation=n", use_sudo=True)
            log.info("Successfully disabled signature validation via config (Debug.EnableSignatureValidation=n)")
            log.info("*** Test cleanup complete.")


if __name__ == "__main__":
    ExtSignatureValidation.run_from_command_line()
