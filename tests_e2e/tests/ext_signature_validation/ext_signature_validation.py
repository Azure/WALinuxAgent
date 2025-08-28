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
import json
import uuid
from typing import Any
from assertpy import fail

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
            extension_case.extension.enable(settings=extension_case.settings, auto_upgrade_minor_version=False)
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

    def _should_uninstall_extension(self, extension_case):
        log.info("")
        log.info(f"Deleting extension {extension_case.extension}, should succeed")
        extension_case.extension.delete()
        instance_view_extensions = self._context.vm.get_instance_view().extensions
        if instance_view_extensions is not None and any(e.name == extension_case.extension._resource_name for e in instance_view_extensions):
            raise Exception(f"extension {extension_case.extension} still in instance view after attempting to delete")
        log.info(f"Delete succeeded for {extension_case.extension} as expected")

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

        # TODO: RCv2 fails on AzureCloud for distros with GLIBC < 2.34, so we skip it on those distros in public cloud only.
        # Once RCv2 is updated to support older GLIBC versions, remove the skip logic.
        should_skip_rcv2 = self._context.vm.cloud == "AzureCloud" and not VmExtensionIds.RunCommandHandler.supports_distro(distro)

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
        if not should_skip_rcv2:
            self._should_enable_extension(run_command_signed, should_validate_signature=True)
            self._should_uninstall_extension(run_command_signed)
        else:
            log.info("Skipping test case because RunCommandHandler is currently having issues on distro '{0}'".format(distro))


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
        ext_to_enable = [custom_script_signed, vm_access_signed, application_health_signed]
        if not should_skip_rcv2:
            ext_to_enable.append(run_command_signed)
        self._should_enable_multiple_signed_extensions(ext_to_enable)


if __name__ == "__main__":
    ExtSignatureValidation.run_from_command_line()
