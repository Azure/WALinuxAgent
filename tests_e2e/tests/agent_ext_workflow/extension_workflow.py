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

from azure.mgmt.compute.models import VirtualMachineExtensionInstanceView
from assertpy import soft_assertions, assert_that
from datetime import datetime
from random import choice
import uuid

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


def str_to_encoded_ustr(s, encoding='utf-8'):
    try:
        # For py3+, str() is unicode by default
        if isinstance(s, bytes):
            # str.encode() returns bytes which should be decoded to get the str.
            return s.decode(encoding)
        else:
            # If its not encoded, just return the string
            return str(s)
    except Exception:
        # If some issues in decoding, just return the string
        return str(s)


class ExtensionWorkflow(AgentTest):
    """
    This scenario tests if the correct extension workflow sequence is being executed from the agent. See README for
    details on GuestAgentDcrTestExtension.
    """
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

    # This class represents the GuestAgentDcrTestExtension running on the test VM
    class GuestAgentDcrTestExtension:
        COUNT_KEY_NAME = "Count"
        NAME_KEY_NAME = "name"
        DATA_KEY_NAME = "data"

        def __init__(self, extension: VirtualMachineExtensionClient, ssh_client: SshClient, version: str):
            self.extension = extension
            self.name = "GuestAgentDcrTestExt"
            self.version = version
            self.message = ""
            self.enable_count = 0
            self.ssh_client = ssh_client
            self.data = None

        def modify_ext_settings_and_enable(self, data=None):
            self.enable_count += 1
            setting_name = "%s-%s, %s: %s" % (self.name, self.version, self.COUNT_KEY_NAME, self.enable_count)
            if data is not None:
                setting_name = "{0}, {1}: {2}".format(setting_name, self.DATA_KEY_NAME, data)
            self.message = setting_name
            settings = {self.NAME_KEY_NAME: setting_name.encode('utf-8')}

            log.info("Add or update extension {0} with settings {1}".format(self.extension, settings))
            self.extension.enable(settings=settings, auto_upgrade_minor_version=False)

        def assert_instance_view(self, data=None):
            if data is None:
                self.extension.assert_instance_view(expected_version=self.version, expected_message=self.message)
            else:
                self.data = data
                self.extension.assert_instance_view(expected_version=self.version, assert_function=self.assert_data)

        def assert_data(self, instance_view: VirtualMachineExtensionInstanceView):
            log.info("Asserting extension status ...")
            status_message = instance_view.statuses[0].message

            log.info("Status message: %s" % status_message)

            expected_ext_version = "%s-%s" % (self.name, self.version)
            assert_that(expected_ext_version in status_message).described_as(
                f"Specific extension version name should be in the InstanceView message ({expected_ext_version})").is_true()

            expected_count = "%s: %s" % (self.COUNT_KEY_NAME, self.enable_count)
            assert_that(expected_count in status_message).described_as(
                f"Expected count should be in the InstanceView message ({expected_count})").is_true()

            if self.data is not None:
                expected_data = "{0}: {1}".format(self.DATA_KEY_NAME, self.data)
                assert_that(expected_data in status_message).described_as(
                    f"Expected data should be in the InstanceView message ({expected_data})").is_true()

        def execute_assert(self, file_name, args):
            log.info("Asserting %s %s ...", file_name, ' '.join(args))

            log.info("Running {0} remotely with arguments {1}".format(file_name, args))
            result = self.ssh_client.run_command(f"{file_name} {args}", use_sudo=True)

            with soft_assertions():
                assert_that(result).described_as("Assertion for file '{0}' with args: {1}".format(file_name, args)).is_true()

        def restart_agent_and_test_status(self, command_args: list[str], assert_status: bool = False):
            # Restarting agent should just run enable again and rerun the same settings
            output = self.ssh_client.run_command("agent-service restart", use_sudo=True)
            log.info("Restart completed:\n%s", output)

            for args in command_args:
                self.execute_assert('assert-operation-sequence.py', args)

            if assert_status:
                self.assert_instance_view()

            return True

        def assert_scenario(self, file_name: str, command_args: str, assert_status: bool = False, restart_agent: list[str] = None, data: str = None):
            # First assert the instance view
            if assert_status:
                log.info("Assert instance view has expected message for test extension")
                if data is not None:
                    self.assert_instance_view(data)
                else:
                    self.assert_instance_view()

            # Then test the operation sequence (by checking the operations.log file in the VM)
            log.info("Assert operations.log has the expected operation sequence added by the test extension")
            self.execute_assert(file_name, command_args)

            # Then restart the agent and test the status again if enabled (by checking the operations.log file in the VM)
            if restart_agent is not None:
                log.info("Restart the agent and assert operations.log has the expected operation sequence added by the test extension")
                self.restart_agent_and_test_status(command_args=restart_agent, assert_status=assert_status)

        def update_ext_version(self, extension: VirtualMachineExtensionClient, version: str):
            self.extension = extension
            self.version = version

    def run(self):
        is_arm64: bool = self._ssh_client.get_architecture() == "aarch64"

        if is_arm64:
            log.info("Skipping test case for %s, since it has not been published on ARM64", VmExtensionIds.GuestAgentDcrTestExtension)
        else:
            log.info("\n*******Verifying the extension install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Create DcrTestExtension with version 1.1.5
            dcr_test_ext_id_1_1 = VmExtensionIdentifier(
                VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                VmExtensionIds.GuestAgentDcrTestExtension.type,
                "1.1"
            )
            dcr_test_ext_client = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_1,
                resource_name="GuestAgentDcrTestExt"
            )
            dcr_ext = ExtensionWorkflow.GuestAgentDcrTestExtension(
                extension=dcr_test_ext_client,
                ssh_client=self._ssh_client,
                version="1.1.5"
            )

            # Install test extension on the VM
            dcr_ext.modify_ext_settings_and_enable()

            # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
            # sequence for the current test
            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops install enable"
            restart_agent_command_args = [f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops install enable enable"]

            dcr_ext.assert_scenario(
                file_name='assert-operation-sequence.py',
                command_args=command_args,
                assert_status=True,
                restart_agent=restart_agent_command_args
            )

            log.info("\n*******Verifying the extension enable scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Enable test extension on the VM
            dcr_ext.modify_ext_settings_and_enable()

            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops enable"
            restart_agent_command_args = [f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops enable enable"]

            dcr_ext.assert_scenario(
                file_name='assert-operation-sequence.py',
                command_args=command_args,
                assert_status=True,
                restart_agent=restart_agent_command_args
            )

            log.info("\n*******Verifying the extension enable with special characters scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            test_guid = str(uuid.uuid4())
            random_special_char_sentences = [
                "Quizdeltagerne spiste jordbær med fløde, mens cirkusklovnen Wolther spillede på xylofon.",
                "Falsches Üben von Xylophonmusik quält jeden größeren Zwerg",
                "Zwölf Boxkämpfer jagten Eva quer über den Sylter Deich",
                "Heizölrückstoßabdämpfung",
                "Γαζέες καὶ μυρτιὲς δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο",
                "Ξεσκεπάζω τὴν ψυχοφθόρα βδελυγμία",
                "El pingüino Wenceslao hizo kilómetros bajo exhaustiva lluvia y frío, añoraba a su querido cachorro.",
                "Portez ce vieux whisky au juge blond qui fume sur son île intérieure, à côté de l'alcôve ovoïde, où les bûches"
            ]
            sentence = str_to_encoded_ustr(choice(random_special_char_sentences))
            test_str = "{0}; Special chars: {1}".format(test_guid, sentence)

            log.info("Special char test string for {0}: {1}".format(dcr_test_ext_client, test_str))
            dcr_ext.modify_ext_settings_and_enable(data=test_str)

            command_args = f"--data {test_guid}"

            # We first ensure that the stdout contains the special characters and then we check if the test_guid is logged
            # atleast once in the agent log to ensure that there were no errors when handling special characters in the agent
            dcr_ext.assert_scenario(
                file_name='check-data-in-agent-log.py',
                command_args=command_args,
                assert_status=True,
                data=test_guid
            )

            log.info("\n*******Verifying the extension uninstall scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops disable uninstall"
            restart_agent_command_args=[f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops disable uninstall"]

            log.info("Delete %s", dcr_test_ext_client)
            # TODO: Add polling for this async operation?
            dcr_ext.extension.delete()

            dcr_ext.assert_scenario(
                file_name='assert-operation-sequence.py',
                command_args=command_args,
                restart_agent=restart_agent_command_args
            )

            log.info("\n*******Verifying the extension update with install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            new_version_update_mode_with_install = "1.2.0"
            old_version = "1.1.5"

            # Create DcrTestExtension with version 1.1 and 1.2
            dcr_test_ext_id_1_2 = VmExtensionIdentifier(
                VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                VmExtensionIds.GuestAgentDcrTestExtension.type,
                "1.2"
            )
            dcr_test_ext_client_1_2 = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_2,
                resource_name="GuestAgentDcrTestExt"
            )
            dcr_ext = ExtensionWorkflow.GuestAgentDcrTestExtension(
                extension=dcr_test_ext_client,
                ssh_client=self._ssh_client,
                version=old_version
            )

            # Install test extension v1.1.5 on the VM and assert instance view
            dcr_ext.modify_ext_settings_and_enable()
            dcr_ext.assert_instance_view()

            # Update extension object & version to new version
            dcr_ext.update_ext_version(dcr_test_ext_client_1_2, new_version_update_mode_with_install)

            # Install test extension v1.2.0 on the VM and assert instance view
            dcr_ext.modify_ext_settings_and_enable()
            dcr_ext.assert_instance_view()

            # TODO: removed update in second set of restart agent test args -> check that this is allowed/expected
            command_args = f"--start-time {start_time} update_sequence --old-version {old_version} --old-ver-ops disable uninstall --new-version {new_version_update_mode_with_install} --new-ver-ops update install enable --final-ops disable update uninstall install enable"
            restart_agent_command_args = [
                f"--start-time {start_time} normal_ops_sequence --version {old_version} --ops disable uninstall",
                f"--start-time {start_time} normal_ops_sequence --version {new_version_update_mode_with_install} --ops install enable enable"
            ]

            dcr_ext.assert_scenario(
                file_name='assert-operation-sequence.py',
                command_args=command_args,
                assert_status=True,
                restart_agent=restart_agent_command_args
            )
            # TODO: add polling for delete operation?
            dcr_ext.extension.delete()

            log.info("\n*******Verifying the extension update without install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            new_version_update_mode_without_install = "1.3.0"

            # Create DcrTestExtension with version 1.1 and 1.3
            dcr_test_ext_id_1_3 = VmExtensionIdentifier(
                VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                VmExtensionIds.GuestAgentDcrTestExtension.type,
                "1.3")
            dcr_test_ext_client_1_3 = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_3,
                resource_name="GuestAgentDcrTestExt"
            )
            dcr_ext = ExtensionWorkflow.GuestAgentDcrTestExtension(
                extension=dcr_test_ext_client,
                ssh_client=self._ssh_client,
                version=old_version
            )

            # Install test extension v1.1.5 on the VM and assert instance view
            dcr_ext.modify_ext_settings_and_enable()
            dcr_ext.assert_instance_view()

            # Update extension object & version to new version
            dcr_ext.update_ext_version(dcr_test_ext_client_1_3, new_version_update_mode_without_install)

            # Install test extension v1.3.0 on the VM and assert instance view
            dcr_ext.modify_ext_settings_and_enable()
            dcr_ext.assert_instance_view()

            # TODO: removed update in second set of restart agent test args -> check that this is allowed/expected
            command_args = f"--start-time {start_time} update_sequence --old-version {old_version} --old-ver-ops disable uninstall --new-version {new_version_update_mode_without_install} --new-ver-ops update enable --final-ops disable update uninstall enable"
            restart_agent_command_args = [
                f"--start-time {start_time} normal_ops_sequence --version {old_version} --ops disable uninstall",
                f"--start-time {start_time} normal_ops_sequence --version {new_version_update_mode_without_install} --ops enable enable"
            ]

            dcr_ext.assert_scenario(
                file_name='assert-operation-sequence.py',
                command_args=command_args,
                assert_status=True,
                restart_agent=restart_agent_command_args
            )

            log.info("\n*******Verifying no lag between agent start and gs processing*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            log.info("Running validate-no-lag-between-agent-start-and-gs-processing.py remotely...")
            result = self._ssh_client.run_command("validate-no-lag-between-agent-start-and-gs-processing.py", use_sudo=True)
            with soft_assertions():
                assert_that(result).described_as("Validation for no lag time result").is_empty()


if __name__ == "__main__":
    ExtensionWorkflow.run_from_command_line()
