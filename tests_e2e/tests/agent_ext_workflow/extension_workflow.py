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

#
# BVT for extension install.
#

from assertpy import soft_assertions, assert_that
from datetime import datetime
from random import choice
import re
import uuid
from datetime import timedelta

from pathlib import Path
from tests_e2e.tests.lib.agent_log import AgentLog
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
    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = SshClient(
            ip_address=self._context.vm_ip_address,
            username=self._context.username,
            private_key_file=self._context.private_key_file)

    class GuestAgentDcrTestExtension:
        COUNT_KEY_NAME = "Count"
        NAME_KEY_NAME = "name"
        DATA_KEY_NAME = "data"
        VERSION_KEY_NAME = "version"
        ASSERT_STATUS_KEY_NAME = "assert_status"
        RESTART_AGENT_KEY_NAME = "restart_agent"

        def __init__(self, extension: VirtualMachineExtensionClient, ssh_client: SshClient):
            self.extension = extension
            self.name = "GuestAgentDcr-TestInstall"
            self.version = "1.1.5"
            self.message = ""
            self.enable_count = 0
            self.ssh_client = ssh_client

        def modify_ext_settings_and_enable(self, data=None):
            self.enable_count += 1
            setting_name = "%s-%s, %s: %s" % (self.name, self.version, self.COUNT_KEY_NAME, self.enable_count)
            if data is not None:
                setting_name = "{0}, {1}: {2}".format(setting_name, self.DATA_KEY_NAME, data)
            log.info("The settings_name before encode is {0}".format(setting_name))
            settings = {self.NAME_KEY_NAME: setting_name.encode('utf-8')}
            log.info("The settings after encode is {0}".format(settings.get(self.NAME_KEY_NAME)))
            self.extension.enable(settings=settings, auto_upgrade_minor_version=False)
            self.message = setting_name

        def assert_instance_view(self, assert_function=None):
            self.extension.assert_instance_view(expected_version=self.version, expected_message=self.message, assert_function=assert_function)

        def assert_extension_status(self):
            return
            # if data is not None:
            #     if "{0}: {1}".format(self.DATA_KEY_NAME, data) not in status_message:
            #         raise Exception("Data did not match in status message: %s!\nExpected Data: %s"
            #                         % (status_message, data))
            # return True

        def execute_assert(self, file_name, args):
            log.info("Asserting %s %s ...", file_name, ' '.join(args))

            # ssh_client.run_command(f"chmod +700 {file_name}")
            result = self.ssh_client.run_command(f"{file_name} {args}", use_sudo=True)

            with soft_assertions():
                assert_that(result).described_as(f"Assertion for file '%s' with args: %s" % (file_name, args)).is_true()

        def restart_agent_and_test_status(self, test_args):
            # Restarting agent should just run enable again and rerun the same settings
            output = self.ssh_client.run_command("agent-service restart", use_sudo=True)
            log.info("Restart completed:\n%s", output)

            for restart_args in test_args['restart_agent_test_args']:
                self.execute_assert('assert-operation-sequence.py', restart_args)

            if test_args['assert_status']:
                self.assert_instance_view()

            return True

        def assert_scenario(self, file_name, test_args, command_args):
            # First test the status blob (that we get by using the Azure SDK)
            if self.ASSERT_STATUS_KEY_NAME in test_args and test_args[self.ASSERT_STATUS_KEY_NAME]:
                log.info("Assert instance view has expected message for test extension")
                self.assert_instance_view()

            # Then test the operation sequence (by checking the operations.log file in the VM)
            log.info("Assert operations.log has the expected operation sequence added by the test extension")
            self.execute_assert(file_name, command_args)

            # Then restart the agent and test the status again if enabled (by checking the operations.log file in the VM)
            if self.RESTART_AGENT_KEY_NAME in test_args and test_args[self.RESTART_AGENT_KEY_NAME]:
                log.info("Restart the agent and assert operations.log has the expected operation sequence added by the test extension")
                self.restart_agent_and_test_status(test_args)

    def validate_no_time_lag_between_agent_start_and_gs_processing(self):
        success = True

        agent_started_time = []
        agent_msg = []
        time_diff_max_secs = 15

        # Example: Agent WALinuxAgent-2.2.47.2 is running as the goal state agent
        agent_started_regex = r"Azure Linux Agent \(Goal State Agent version [0-9.]+\)"
        gs_completed_regex = r"ProcessExtensionsGoalState completed\s\[(?P<id>[a-z_\d]+)\s(?P<duration>\d+)\sms\]"

        verified_atleast_one_log_line = False
        verified_atleast_one_agent_started_log_line = False
        verified_atleast_one_gs_complete_log_line = False

        agent_log = AgentLog(Path('/var/log/waagent.log'))

        try:
            for agent_record in agent_log.read():
                verified_atleast_one_log_line = True

                agent_started = re.match(agent_started_regex, agent_record.text)
                verified_atleast_one_agent_started_log_line = verified_atleast_one_agent_started_log_line or agent_started
                if agent_started:
                    agent_started_time.append(agent_record.timestamp)
                    agent_msg.append(agent_record.text)

                gs_complete = re.match(gs_completed_regex, agent_record.text)
                verified_atleast_one_gs_complete_log_line = verified_atleast_one_gs_complete_log_line or gs_complete
                if agent_started_time and gs_complete:
                    duration = gs_complete.group('duration')
                    diff = agent_record.timestamp - agent_started_time.pop()
                    # Reduce the duration it took to complete the Goalstate, essentially we should only care about how long
                    # the agent took after start/restart to start processing GS
                    diff -= timedelta(milliseconds=int(duration))
                    agent_msg_line = agent_msg.pop()
                    if diff.seconds > time_diff_max_secs:
                        success = False
                        log.info("Found delay between agent start and GoalState Processing > {0}secs: "
                              "Messages: \n {1} {2}".format(time_diff_max_secs, agent_msg_line, agent_record.text))

        except IOError as e:
            log.info("Unable to validate no lag time: {1}".format(str(e)))

        if not verified_atleast_one_log_line:
            success = False
            log.info("Didn't parse a single log line, ensure the log_parser is working fine and verify log regex")

        if not verified_atleast_one_agent_started_log_line:
            success = False
            print("Didn't parse a single agent started log line, ensure the Regex is working fine: {0}"
                  .format(agent_started_regex))

        if not verified_atleast_one_gs_complete_log_line:
            success = False
            print("Didn't parse a single GS completed log line, ensure the Regex is working fine: {0}"
                  .format(gs_completed_regex))

        if agent_started_time or agent_msg:
            success = False
            print("Mismatch between number of agent start messages and number of GoalState Processing messages\n "
                  "Agent Start Messages: \n {0}".format('\n'.join(agent_msg)))

        return success

    def run(self):
        is_arm64: bool = self._ssh_client.get_architecture() == "aarch64"

        if is_arm64:
            log.info("Skipping test case for %s, since it has not been published on ARM64", VmExtensionIds.GuestAgentDcrTestExtension)
        else:
            log.info("*******Verifying the extension install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Create DcrTestExtension
            dcr_test_ext_id_1_1 = VmExtensionIdentifier(VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                                                    VmExtensionIds.GuestAgentDcrTestExtension.type, "1.1")
            dcr_test_ext_client = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_1,
                resource_name="GuestAgentDcr-TestInstall")
            dcr_ext = ExtensionWorkflow.GuestAgentDcrTestExtension(extension=dcr_test_ext_client, ssh_client=self._ssh_client)

            log.info("Installing %s", dcr_test_ext_client)
            dcr_ext.modify_ext_settings_and_enable()

            # Test arguments specify the specific arguments for this test
            # restart_agent_test_args are the parameters that we pass to the assert-operation-sequence.py file to verify
            # the operation sequence after restarting the agent
            test_args = {
                dcr_ext.ASSERT_STATUS_KEY_NAME: True,
                dcr_ext.RESTART_AGENT_KEY_NAME: True,
                dcr_ext.VERSION_KEY_NAME: dcr_ext.version,
                'restart_agent_test_args': [
                    f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops install enable enable"]
            }

            # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
            # sequence for the current test
            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops install enable"

            dcr_ext.assert_scenario('assert-operation-sequence.py', test_args, command_args)

            log.info("*******Verifying the extension enable scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            log.info("Call enable on %s", dcr_test_ext_client)
            dcr_ext.modify_ext_settings_and_enable()

            # Test arguments specify the specific arguments for this test
            # restart_agent_test_args are the parameters that we pass to the assert-operation-sequence.py file to verify
            # the operation sequence after restarting the agent
            test_args = {
                dcr_ext.ASSERT_STATUS_KEY_NAME: True,
                dcr_ext.RESTART_AGENT_KEY_NAME: True,
                dcr_ext.VERSION_KEY_NAME: dcr_ext.version,
                'restart_agent_test_args': [
                    f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops enable enable"]
            }

            # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
            # sequence for the current test
            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops enable"

            dcr_ext.assert_scenario('assert-operation-sequence.py', test_args, command_args)

            log.info("*******Verifying the extension enable with special characters scenario*******")

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
            log.info("The sentence is: {0}".format(sentence))
            test_str = "{0}; Special chars: {1}".format(test_guid, sentence)
            log.info("Special char test string for {0}: {1}".format(dcr_test_ext_client, test_str))
            dcr_ext.modify_ext_settings_and_enable(data=test_str)

            # Test arguments specify the specific arguments for this test
            test_args = {
                dcr_ext.ASSERT_STATUS_KEY_NAME: True,
                dcr_ext.VERSION_KEY_NAME: dcr_ext.version,
                dcr_ext.DATA_KEY_NAME: test_guid
            }
            # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
            # sequence for the current test
            command_args = ['--data', test_guid]

            # We first ensure that the stdout contains the special characters and then we check if the test_guid is logged
            # atleast once in the agent log to ensure that there were no errors when handling special characters in the agent
            dcr_ext.assert_scenario('check-data-in-agent-log.py', test_args, command_args)

            log.info("*******Verifying the extension uninstall scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Test arguments specify the specific arguments for this test
            # restart_agent_test_args are the parameters that we pass to the assert-operation-sequence.py file to verify
            # the operation sequence after restarting the agent
            test_args = {
                dcr_ext.ASSERT_STATUS_KEY_NAME: False,
                dcr_ext.RESTART_AGENT_KEY_NAME: True,
                dcr_ext.VERSION_KEY_NAME: dcr_ext.version,
                'restart_agent_test_args': [
                    f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops disable uninstall"]
            }

            # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
            # sequence for the current test
            command_args = f"--start-time {start_time} normal_ops_sequence --version {dcr_ext.version} --ops disable uninstall"

            log.info("Delete %s", dcr_test_ext_client)
            # TODO: Add polling for this async operation?
            dcr_ext.extension.delete()
            dcr_ext.assert_scenario('assert-operation-sequence.py', test_args, command_args)

            log.info("*******Verifying the extension update with install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            new_version_update_mode_with_install = "1.2.0"
            old_version = "1.1.5"

            # Create DcrTestExtension with version 1.2
            dcr_test_ext_id_1_2 = VmExtensionIdentifier(VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                                                    VmExtensionIds.GuestAgentDcrTestExtension.type, "1.2")
            dcr_test_ext_client_1_1 = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_1,
                resource_name="GuestAgentDcr-TestInstall")
            dcr_test_ext_client_1_2 = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_2,
                resource_name="GuestAgentDcr-TestInstall")

            # After asserting 1.1, update extension object + version in GuestAgentDcrTestExtension before asserting 1.2
            dcr_ext_1_1 = ExtensionWorkflow.GuestAgentDcrTestExtension(extension=dcr_test_ext_client, ssh_client=self._ssh_client)

            log.info("Installing %s, version %s", dcr_test_ext_client, "1.1.5")
            dcr_ext_1_1.modify_ext_settings_and_enable()
            dcr_ext_1_1.assert_instance_view()

            dcr_ext_1_1.extension = dcr_test_ext_client_1_2
            dcr_ext_1_1.version = "1.2.0"
            log.info("Installing %s, version %s", dcr_test_ext_client, "1.2.0")
            dcr_ext_1_1.modify_ext_settings_and_enable()
            dcr_ext_1_1.assert_instance_view()

            # Here I removed update in second set of restart agent test args -> check that this is allowed
            test_args = {
                dcr_ext_1_1.ASSERT_STATUS_KEY_NAME: True,
                dcr_ext_1_1.RESTART_AGENT_KEY_NAME: True,
                dcr_ext_1_1.VERSION_KEY_NAME: new_version_update_mode_with_install,
                'restart_agent_test_args': [f"--start-time {start_time} normal_ops_sequence --version {old_version} --ops disable uninstall",
                                            f"--start-time {start_time} normal_ops_sequence --version {new_version_update_mode_with_install} --ops install enable enable"]
            }
            command_args = f"--start-time {start_time} update_sequence --old-version {old_version} --old-ver-ops disable uninstall --new-version {new_version_update_mode_with_install} --new-ver-ops update install enable --final-ops disable update uninstall install enable"

            dcr_ext_1_1.assert_scenario('assert-operation-sequence.py', test_args, command_args)
            dcr_ext_1_1.extension.delete()

            log.info("*******Verifying the extension update without install scenario*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            new_version_update_mode_with_install = "1.3.0"
            old_version = "1.1.5"

            # Create DcrTestExtension with version 1.2
            dcr_test_ext_id_1_3 = VmExtensionIdentifier(VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                                                        VmExtensionIds.GuestAgentDcrTestExtension.type, "1.3")
            dcr_test_ext_client_1_3 = VirtualMachineExtensionClient(
                self._context.vm,
                dcr_test_ext_id_1_3,
                resource_name="GuestAgentDcr-TestInstall")

            # After asserting 1.1, update extension object + version in GuestAgentDcrTestExtension before asserting 1.2
            dcr_ext_1_1 = ExtensionWorkflow.GuestAgentDcrTestExtension(extension=dcr_test_ext_client,
                                                                       ssh_client=self._ssh_client)

            log.info("Installing %s, version %s", dcr_test_ext_client, "1.1.5")
            dcr_ext_1_1.modify_ext_settings_and_enable()
            dcr_ext_1_1.assert_instance_view()

            dcr_ext_1_1.extension = dcr_test_ext_client_1_3
            dcr_ext_1_1.version = "1.3.0"
            log.info("Installing %s, version %s", dcr_test_ext_client, "1.3.0")
            dcr_ext_1_1.modify_ext_settings_and_enable()
            dcr_ext_1_1.assert_instance_view()

            # Here I removed update in second set of restart agent test args -> check that this is allowed
            test_args = {
                dcr_ext_1_1.ASSERT_STATUS_KEY_NAME: True,
                dcr_ext_1_1.RESTART_AGENT_KEY_NAME: True,
                dcr_ext_1_1.VERSION_KEY_NAME: new_version_update_mode_with_install,
                'restart_agent_test_args': [
                    f"--start-time {start_time} normal_ops_sequence --version {old_version} --ops disable uninstall",
                    f"--start-time {start_time} normal_ops_sequence --version {new_version_update_mode_with_install} --ops enable enable"]
            }
            command_args = f"--start-time {start_time} update_sequence --old-version {old_version} --old-ver-ops disable uninstall --new-version {new_version_update_mode_with_install} --new-ver-ops update enable --final-ops disable update uninstall enable"

            dcr_ext_1_1.assert_scenario('assert-operation-sequence.py', test_args, command_args)

            log.info("*******Verifying no lag between agent start and gs processing*******")

            # Record the time we start the test
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            assert_that(self.validate_no_time_lag_between_agent_start_and_gs_processing()).described_as("Validate no lag time between agent start and goal state processing").is_true()




if __name__ == "__main__":
    ExtensionWorkflow.run_from_command_line()