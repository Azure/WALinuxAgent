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
from typing import List, Dict, Any

from assertpy import fail

from azurelinuxagent.common.future import ustr
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier, VmExtensionIds


class CheckFallbackToDirect(AgentVmTest):
    """
    This test adds a DROP rule on outbound requests on the HGAP port and verifies that the agent falls back to the
    Direct download channel.
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Delete all extensions on VM to reduce the amount of manifest downloads attempted in the agent after we block
        # outbound requests to HGAP port. Test will be too long if we keep all extensions in the GS.
        extensions_on_vm = self._context.vm.get_extensions().value
        for ext in extensions_on_vm:
            ext_name = ext.name
            log.info(f"Removing {ext_name}...")
            VirtualMachineExtensionClient(self._context.vm,
                                          VmExtensionIdentifier(publisher=ext.publisher,
                                                                ext_type=ext.type_properties_type,
                                                                version=ext.type_handler_version),
                                          resource_name=ext_name).delete()
            log.info(f"Deleted {ext_name}.")

        # Stop the agent service
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Add a DROP rule for outbound requests to HGAP port
        log.info("")
        log.info("Adding DROP rule for outbound requests to HGAP port...")
        self._run_remote_test(ssh_client, "no_outbound_connections-manage_firewall_rule.py --action add", use_sudo=True)

        #  Disable FastTrack to avoid errors fetching VmSettings which would block goal state processing
        #  Disable Firewall to prevent the agent from resetting the firewall rules
        #  Restart the agent
        log.info("")
        log.info("Disabling FastTrack, firewall, and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=n OS.EnableFirewall=n'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Start the CSE installation. Do not wait for the operation to finish at the CRP level, as we need to reapply
        # the VM to force a new incarnation for the extension to be processed since FastTrack is disabled.
        log.info("")
        log.info("Starting CSE installation...")
        custom_script = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)
        timeout = 10
        try:
            custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"}, timeout=timeout)
        except TimeoutError as e:
            # Timeout is expected.
            if f"[Enable Microsoft.Azure.Extensions.CustomScript] did not complete within {timeout} seconds" not in ustr(e):
                fail(f"Caught unexpected TimeoutError while trying to install CSE:\n{e}")
            log.info("Test will not wait for CSE operation to finish at CRP level since a new incarnation needs to be "
                     "forced with vm reapply for the extension to be processed.")
            # The agent is only fetching goal states via WireServer. Reapply the VM so that the incarnation is quickly
            # incremented.
            log.info("")
            log.info("Reapplying the VM to force new incarnation...")
            self._context.vm.reapply()

        # Check the status of custom script to assert that it was installed successfully
        log.info("")
        log.info("Asserting CSE was installed successfully...")
        custom_script.assert_instance_view()

        # Check the agent log to verify that the agent did fall back to Direct download channel
        log.info("")
        log.info("Checking agent log to verify that agent did fall back to Direct download channel...")
        expected_message = 'Default channel changed to Direct channel.'
        command = f"check_data_in_agent_log.py --data '{expected_message}'"
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
        log.info("Found agent log indicating that the agent switched to the Direct channel.")

        # Clean up test VM so that it can be shared with other tests
        # Stop the agent service
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Delete DROP rule for outbound requests to HGAP port
        log.info("")
        log.info("Deleting DROP rule for outbound requests to HGAP port...")
        self._run_remote_test(ssh_client, "no_outbound_connections-manage_firewall_rule.py --action delete",
                              use_sudo=True)

        #  Re-enable FastTrack and Firewall. Restart the agent.
        log.info("")
        log.info("Re-enabling FastTrack, firewall, and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=y OS.EnableFirewall=y'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            #
            # Outbound requests to HGAP port is blocked, so the following are expected:
            #
            # 2025-10-01T21:56:59.368921Z ERROR ExtHandler ExtHandler HostGAPlugin: Exception Get API versions: [HttpError] [HTTP Failed] GET http://168.63.129.16:32526/versions -- IOError timed out -- 6 attempts made
            # 2025-10-01T21:56:59.377474Z ERROR ExtHandler ExtHandler Event: name=WALinuxAgent, op=HealthObservation, message={"ObservationName": "GuestAgentPluginVersions", "IsHealthy": false, "Description": "", "Value": ""}, duration=0
            # 2025-10-01T21:56:59.378208Z ERROR ExtHandler ExtHandler Event: name=WALinuxAgent, op=InitializeHostPlugin, message=, duration=0
            #
            {
                'message': r"HostGAPlugin: Exception Get API versions: \[HttpError\] \[HTTP Failed\] GET http://168.63.129.16:32526/versions"
            },
            {
                'message': r"Event: name=WALinuxAgent, op=HealthObservation, message=.*\"ObservationName\": \"GuestAgentPluginVersions\".*"
            },
            {
                'message': r"Event: name=WALinuxAgent, op=InitializeHostPlugin, message=, duration=0"
            }
        ]


if __name__ == "__main__":
    CheckFallbackToDirect.run_from_command_line()

