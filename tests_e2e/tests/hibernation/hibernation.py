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

from assertpy import fail
from typing import List, Dict, Any

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachine
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds


class Hibernation(AgentVmTest):
    """
    A hibernate/resume cycle is a special case in that resume produces a new Fabric goal state with incarnation 1. Since the VM is re-allocated,
    that goal state will include a new tenant encryption certificate. If the incarnation was also 1 before hibernation, the Agent won't detect
    this new goal state and subsequent Fast Track goal states would fail because they require the new certificate.

    The Agent has logic to detect this scenario and fetch the required certificates; this test verifies that logic.

    See https://learn.microsoft.com/en-us/azure/virtual-machines/linux/hibernate-resume-linux for details on hibernation
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def run(self):
        log.info("Executing test on %s - IP address: %s", self._context.vm, self._context.ip_address)

        #
        # Ensure hibernation is enabled
        #
        self._enable_hibernation()

        #
        # Check that the current incarnation is 1; if that is not the case, do a hibernate-resume cycle to reset the incarnation to 1
        #
        log.info("Retrieving current incarnation...")
        incarnation = self._ssh_client.run_command("get_goal_state.py --properties incarnation", use_sudo=True).rstrip()
        if incarnation != "1":
            self._do_hibernate_resume_cycle()
            incarnation = self._ssh_client.run_command("get_goal_state.py --properties incarnation", use_sudo=True).rstrip()
            if incarnation != "1":
                raise Exception(f"The incarnation was not reset to 1 after a hibernate-resume cycle. Incarnation is {incarnation}")
        log.info("The current incarnation is 1")

        #
        # Do a hibernate-resume cycle; this will generate a new tenant certificate but, since the incarnation has not changed,
        # the Agent will not download it yet.
        #
        log.info("Retrieving tenant certificate before hibernation...")
        pre_hibernation_tenant_certificate = self._get_tenant_certificate()
        log.info("Tenant certificate: %s", pre_hibernation_tenant_certificate)

        log.info("Triggering a hibernate-resume cycle to test the tenant certificate...")
        self._do_hibernate_resume_cycle()

        log.info("Retrieving current incarnation...")
        incarnation = self._ssh_client.run_command("get_goal_state.py --properties incarnation", use_sudo=True).rstrip()
        if incarnation != "1":
            raise Exception(f"Unexpected behavior: The incarnation is not 1 after a hibernate-resume cycle. Incarnation is {incarnation}")
        log.info("The current incarnation is 1")

        log.info("Checking tenant certificate after resume...")
        post_hibernation_tenant_certificate = self._get_tenant_certificate()
        if post_hibernation_tenant_certificate == pre_hibernation_tenant_certificate:
            raise Exception("Unexpected behavior: hibernate-resume did not create a new tenant certificate")
        log.info("Tenant certificate: %s", post_hibernation_tenant_certificate)
        log.info("Checking that the new tenant certificate has not been downloaded yet...")
        downloaded = self._ssh_client.run_command(f"ls /var/lib/waagent/{post_hibernation_tenant_certificate}.* || true", use_sudo=True).rstrip()
        if downloaded != "":
            raise Exception(f"Unexpected behavior: The new tenant certificate was downloaded after resume: {downloaded}")
        log.info("The new tenant certificate has not been downloaded yet.")

        #
        # Execute an extension with protected settings and verify that the new tenant certificate was downloaded.
        #
        log.info("Executing an extension with protected settings to verify it can use the new tenant certificate")
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        message = str(uuid.uuid4())
        custom_script.enable(protected_settings={'commandToExecute': f"echo \'{message}\'"}, force_update=True)
        custom_script.assert_instance_view(expected_message=message)

        log.info("Checking that the new tenant certificate was downloaded...")
        downloaded = self._ssh_client.run_command("find /var/lib/waagent -name '*.crt'", use_sudo=True)
        if f"/var/lib/waagent/{post_hibernation_tenant_certificate}.crt" not in downloaded:
            fail(f"The new tenant certificate ({post_hibernation_tenant_certificate}) was not downloaded:\n{downloaded}")
        log.info("The new tenant certificate was downloaded.")

    def _get_tenant_certificate(self) -> str:
        certificates = json.loads(self._ssh_client.run_command("get_goal_state.py --certificates --json", use_sudo=True))
        candidates = [c["thumbprint"] for c in certificates if c["hasPrivateKey"]]
        if len(candidates) != 1:
            raise Exception(f"Could not find the tenant certificate. Current certificates: {certificates}")
        return candidates[0]

    def _enable_hibernation(self) -> None:
        #
        # The test may be running on an existing machine where hibernation has already been set as an additional capability, so we check that before setting it.
        #
        log.info("Enabling hibernation on %s", self._context.vm)
        model: VirtualMachine = self._context.vm.get_model(include_instance_view=True)
        if model.additional_capabilities is not None and model.additional_capabilities.hibernation_enabled:
            log.info("Hibernation is already an additional capability of %s", self._context.vm)
        else:
            #
            # To enable hibernation, the machine must be deallocated, then the hibernationEnabled property must be set, and, lastly, the machine must be reallocated
            #
            log.info("Deallocating %s in order to enable hibernation", self._context.vm)
            self._context.vm.deallocate()
            log.info("Adding hibernation as an additional capability to %s", self._context.vm)
            self._context.vm.update(
                {
                    "additionalCapabilities": {
                        "hibernationEnabled": True
                    }
                }
            )
            log.info("Reallocating %s after enabling hibernation", self._context.vm)
            self._context.vm.start()
            self._refresh_ip_address()

        #
        # The test may be running on an existing machine where the Hibernate extension has already been installed, so we check that before installing it.
        #
        if model.instance_view.extensions is not None and any(e for e in model.instance_view.extensions if e.type == "Microsoft.CPlat.Core.LinuxHibernateExtension"):
            log.info("The Hibernation extension is already installed")
        else:
            log.info("Installing the Hibernation extension")
            hibernate = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.Hibernate, resource_name="Hibernate")
            hibernate.enable(auto_upgrade_minor_version=True)

    def _do_hibernate_resume_cycle(self) -> None:
        log.info("Hibernating %s...", self._context.vm)
        self._context.vm.deallocate(hibernate=True)
        log.info("Resuming %s...", self._context.vm)
        self._context.vm.start()
        self._refresh_ip_address()

    def _refresh_ip_address(self) -> None:
        """
        Updates the test contect and the SSH client to reflect the current IP address of the test VM.
        The IP address of a VM can change as the result of a deallocate/allocate cycle.
        """
        log.info("Refreshing IP address of %s...", self._context.vm)
        self._context.refresh_ip_address()
        self._ssh_client = self._context.create_ssh_client()
        log.info("IP address: %s", self._context.ip_address)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # This warning is produced by the test, so it is expected
            #
            #     2025-06-25T22:25:46.077469Z WARNING ExtHandler ExtHandler The extensions goal state is out of sync with the tenant cert. Certificate 60D73AC8321A3B6898C9E4269CEE3AE2A8A49102, needed by Microsoft.GuestConfiguration.ConfigurationforLinux, is missing.
            #
            {
                'message': 'The extensions goal state is out of sync with the tenant cert.',
                'if': lambda r: r.level == "WARNING"
            }
        ]
        return ignore_rules


if __name__ == "__main__":
    Hibernation.run_from_command_line()

