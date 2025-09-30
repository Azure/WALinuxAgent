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
from time import sleep

from assertpy import fail
from typing import Any, Dict, List

from azurelinuxagent.common.future import ustr
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier


class CheckDoesNotSwitchToDirect(AgentVmTest):
    """
    Verifies that the agent does not switch to the direct download channel in the case of HGAP download failures on a
     VM with no outbound connection (direct download will also fail, so the agent shouldn't switch the channel).
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Delete all extensions on VM to reduce the amount of manifest downloads attempted in the agent after we block
        # outbound requests to HGAP port. Test will be too long if we keep all extensions in the GS.
        extensions_on_vm = self._context.vm.get_extensions().value
        for ext in extensions_on_vm:
            ext_name = ext._resource_name
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

        # Attempt to install CSE. This should fail due to failures to fetch the extension manifest (HGAP downloads will
        # fail due to drop rule and Direct downloads will fail due to no outbound connections).
        log.info("")
        log.info("Starting CSE install operation...")
        custom_script = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)
        # The extension will fail to install due to download failures, but the agent will not be able to report
        # status due to the DROP rule and no outbound connectivity, so we set a short timeout to avoid waiting for the
        # operation to fail at the CRP level.
        timeout = 10
        start_time = ssh_client.run_command("date --utc '+%Y-%m-%dT%TZ'").rstrip()  # Record the time we enable CSE
        try:
            custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"}, timeout=timeout)
        except TimeoutError as e:
            # Timeout is expected.
            if f"[Enable Microsoft.Azure.Extensions.CustomScript] did not complete within {timeout} seconds" not in ustr(e):
                fail(f"Caught unexpected TimeoutError while trying to install CSE:\n{e}")
            log.info("Test will not wait for CSE operation to finish at CRP level, as it is expected to fail due to "
                     "download failures. Will check the agent log later in test to assert that CSE failed.")
            # The agent is only fetching goal states via WireServer. Reapply the VM so that the incarnation is quickly
            # incremented.
            try:
                log.info("")
                log.info("Reapplying the VM to force new incarnation...")
                self._context.vm.reapply(timeout=timeout)
            except TimeoutError as ex:
                # Timeout is expected.
                if f"[Reapply {self._context.vm.resource_group}:{self._context.vm.name}] did not complete within {timeout} seconds" not in ustr(ex):
                    fail(f"Caught unexpected TimeoutError while trying to reapply the VM:\n{ex}")
                log.info("Test will not wait for reapply operation to finish at CRP level, as it is expected to fail "
                         "due to extension failures.")
        except Exception as e:
            fail(f"Caught unexpected exception while trying to install CSE:\n{e}")

        # Check the agent log to verify that CSE failed to install due to download failures on the HGAP and direct
        # channels.
        # Wait up to 20 minutes for the agent to process goal state and attempt to install CSE. There will be many
        # retries which will delay goal state processing, so we allow up to 20 minutes.
        for attempt in range(4):
            log.info("")
            log.info("Sleeping 5 minutes before checking agent log for CSE failure...")
            sleep(5*60)
            log.info("Checking agent log to verify that CSE failed to install due to download failures on HGAP and direct channels...")
            try:
                expected_message = r'.*Microsoft.Azure.Extensions.CustomScript.*\[ExtensionError\] Failed to get ext handler pkgs.*\[HttpError\] Download failed both on the primary and fallback channels'
                command = f"check_data_in_agent_log.py --after-timestamp {start_time} --data '{expected_message}'"
                log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
                break
            except CommandError as e:
                if attempt < 3:
                    log.info("CSE has not failed.")
                    continue
                else:
                    fail(f"Could not find agent log indicating that CSE failed:\n{e}")

        # Check the agent log to verify that there is no log indicating that the agent switched to the direct channel
        try:
            log.info("")
            log.info("Checking agent log to verify that agent did not switch to Direct download channel...")
            unexpected_message = 'Default channel changed to Direct channel.'
            command = f"check_data_in_agent_log.py --data '{unexpected_message}'"
            log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
            # We expect check_data_in_agent_log.py to fail because it should not find the expected data. If the script
            # did not fail, fail the test.
            fail("Found agent log indicating that the agent switched to the Direct channel.")
        except CommandError as e:
            # We expect check_data_in_agent_log.py to fail because it did not find the expected data. If it failed for
            # any other reason, the test should fail.
            if 'Did not find data' not in ustr(e):
                fail(f"Caught unexpected exception while checking agent log:\n{e}")
            log.info("Did not find agent log indicating that the agent switched to the Direct channel (as expected).")

        # Remove drop rule for outbound requests to HGAP port and assert that CSE can be installed successfully.
        # Stop the agent service
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Delete DROP rule for outbound requests to HGAP port
        log.info("")
        log.info("Deleting DROP rule for outbound requests to HGAP port...")
        self._run_remote_test(ssh_client, "no_outbound_connections-manage_firewall_rule.py --action delete", use_sudo=True)

        #  Re-enable FastTrack and Firewall. Restart the agent.
        log.info("")
        log.info("Re-enabling FastTrack, firewall, and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=y OS.EnableFirewall=y'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Enable CSE, should succeed now that HGAP downloads are working.
        custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"})
        log.info("CSE succeeded as expected.")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            #
            # Outbound requests to HGAP port is blocked, so the following are expected:
            #
            # 2025-09-26T21:12:25.022926Z ERROR Daemon Daemon HostGAPlugin: Exception Get API versions: [HttpError] [HTTP Failed] GET http://168.63.129.16:32526/versions -- IOError timed out -- 6 attempts made
            # 2025-09-26T21:12:25.033610Z ERROR Daemon Daemon Event: name=WALinuxAgent, op=HealthObservation, message={"Value": "", "ObservationName": "GuestAgentPluginVersions", "Description": "", "IsHealthy": false}, duration=0
            # 2025-09-26T21:12:25.034991Z ERROR Daemon Daemon Event: name=WALinuxAgent, op=InitializeHostPlugin, message=, duration=0
            # 2025-09-26T21:12:25.036403Z WARNING Daemon Daemon Failed to fetch artifacts profile from blob https://md-hdd-xs024ztfcc2p.z33.blob.storage.azure.net/$system/lisa-maddieford-20250926-210017-612-e0-n0.438f7bfa-c766-4595-8b4c-840652f22178.vmSettings?{redacted}
            # 2025-09-26T21:15:27.830942Z WARNING ExtHandler ExtHandler Can't download the artifacts profile blob; will assume the VM is not on hold. [ExtensionDownloadError] Failed to download artifacts profile blob from all URIs. Last error: [HttpError] Download failed both on the primary and fallback channels. Primary: [[ProtocolError] HostGAPlugin: Host plugin channel is not available] Fallback: [[HttpError] [HTTP Failed] GET https://md-hdd-xs024ztfcc2p.z33.blob.storage.azure.net/$system/lisa-maddieford-20250926-210017-612-e0-n0.438f7bfa-c766-4595-8b4c-840652f22178.vmSettings -- IOError timed out -- 6 attempts made]
            # 2025-09-26T21:20:30.678939Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Extensions.CustomScript, op=None, message=[ExtensionError] Failed to get ext handler pkgs
            # 		Inner error: [ProtocolError] Failed to retrieve extension manifest. Error: [ExtensionDownloadError] Timeout downloading extension manifest. Elapsed: 0:05:02.367196 URIs tried: 1/3. Last error: [HttpError] Download failed both on the primary and fallback channels. Primary: [[ProtocolError] HostGAPlugin: Host plugin channel is not available] Fallback: [[HttpError] [HTTP Failed] GET https://umsawhl4grhgzs0z1rmq.blob.core.windows.net/5237dd14-0aad-f051-0fad-1e33e1b63091/5237dd14-0aad-f051-0fad-1e33e1b63091_manifest.xml -- IOError timed out -- 6 attempts made], duration=0
            # 2025-09-26T21:23:32.966850Z ERROR ExtHandler ExtHandler Event: name=WALinuxAgent, op=ExtensionProcessing, message=Failed to report vm agent status: [ProtocolError] Failed to upload status blob via either channel, duration=0
            # 2025-09-26T22:39:22.448658Z WARNING CollectLogsHandler ExtHandler Failed to upload logs. Error: [ProtocolError] HostGAPlugin: HostGAPlugin is not available
            #
            {
                'message': r"HostGAPlugin: Exception Get API versions: \[HttpError\] \[HTTP Failed\] GET http://168.63.129.16:32526/versions"
            },
            {
                'message': r"Event: name=WALinuxAgent, op=HealthObservation, message=.*\"ObservationName\": \"GuestAgentPluginVersions\".*"
            },
            {
                'message': r"Event: name=WALinuxAgent, op=InitializeHostPlugin, message=, duration=0"
            },
            {
                'message': r"Failed to fetch artifacts profile from blob.*"
            },
            {
                'message': r"Can't download the artifacts profile blob; will assume the VM is not on hold."
            },
            {
                'message': r"message=\[ExtensionError\] Failed to get ext handler pkgs"
            },
            {
                'message': r"Failed to report vm agent status: \[ProtocolError\] Failed to upload status blob via either channel"
            },
            {
                'message': r"Failed to upload logs. Error: \[ProtocolError\] HostGAPlugin: HostGAPlugin is not available"
            }
        ]


if __name__ == "__main__":
    CheckDoesNotSwitchToDirect.run_from_command_line()
