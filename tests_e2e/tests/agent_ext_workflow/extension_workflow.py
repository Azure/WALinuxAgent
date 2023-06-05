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

import base64
import uuid
from datetime import datetime

from assertpy import soft_assertions, assert_that

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.identifiers import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


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
        VERSION_KEY_NAME = "version"
        ASSERT_STATUS_KEY_NAME = "assert_status"
        RESTART_AGENT_KEY_NAME = "restart_agent"

        def __init__(self, extension: VirtualMachineExtensionClient):
            self.extension = extension
            self.name = "GuestAgentDcr-TestInstall"
            self.version = "1.1.5"
            self.message = ""
            self.enable_count = 0

        def modify_ext_settings_and_enable(self):
            self.enable_count += 1
            setting_name = "%s-%s, %s: %s" % (self.name, self.version, self.COUNT_KEY_NAME, self.enable_count)
            settings = {self.NAME_KEY_NAME: setting_name.encode('utf-8')}
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

            result = self._ssh_client.run_command(f"{file_name} {args}", use_sudo=True)

            self.logger.info("%s == %s", file_name, result)

            with soft_assertions():
                assert_that(result).described_as(f"Assertion for file '%s' with args: %s" % (file_name, args)).is_true()

        def assert_scenario(self, file_name, test_args, command_args):
            # First test the status blob (that we get by using the Azure SDK)
            if self.ASSERT_STATUS_KEY_NAME in test_args and test_args[self.ASSERT_STATUS_KEY_NAME]:
                self.assert_instance_view()

            # Then test the operation sequence (by checking the operations.log file in the VM)
            self.execute_assert(file_name, command_args)

            # Then restart the agent and test the status again if enabled (by checking the operations.log file in the VM)
            #if self.RESTART_AGENT_KEY_NAME in test_args and test_args[self.RESTART_AGENT_KEY_NAME]:
                #self.restart_agent_and_test_status(test_args)

            return True

        def assert_extension_status(self, test_args):
            # Get status from the SDK
            ext = self.compute_manager.get_vm_extension(vm_name=self.vm_name, ext_name=self.ext_name,
                                                        with_instance_view=True)
            return self.assert_stdout(logger=self.logger, ext=ext, version=test_args[self.VERSION_KEY_NAME],
                                      data=test_args[self.DATA_KEY_NAME] if self.DATA_KEY_NAME in test_args else None)

    def extension_install(self):
        # Record the time we start the test
        start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Create DcrTestExtension
        dcr_test_ext_id = VmExtensionIdentifier(VmExtensionIds.GuestAgentDcrTestExtension.publisher,
                                                VmExtensionIds.GuestAgentDcrTestExtension.type, "1.1")
        dcr_test_ext_client = VirtualMachineExtensionClient(
            self._context.vm,
            dcr_test_ext_id,
            resource_name="GuestAgentDcr-TestInstall")
        dcr_ext = ExtensionWorkflow.GuestAgentDcrTestExtension(extension=dcr_test_ext_client)

        log.info("Installing %s", dcr_test_ext_client)

        dcr_ext.modify_ext_settings_and_enable()
        dcr_ext.assert_instance_view()

        # Test arguments specify the specific arguments for this test
        # restart_agent_test_args are the parameters that we pass to the assert-operation-sequence.py file to verify
        # the operation sequence after restarting the agent
        test_args = {
            dcr_ext.ASSERT_STATUS_KEY_NAME: True,
            dcr_ext.RESTART_AGENT_KEY_NAME: True,
            dcr_ext.VERSION_KEY_NAME: dcr_ext.version,
            'restart_agent_test_args': [['--start-time', start_time,
                                         'normal_ops_sequence',
                                         '--version', dcr_ext.version,
                                         '--ops', 'install', 'enable', 'enable']]
        }

        # command_args are the args we pass to the assert-operation-sequence.py file to verify the operation
        # sequence for the current test
        command_args = ['--start-time', start_time,
                        'normal_ops_sequence', '--version', dcr_ext.version,
                        '--ops', 'install', 'enable']

        dcr_ext.assert_scenario('assert-operation-sequence.py', test_args, command_args)


    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        is_arm64: bool = ssh_client.get_architecture() == "aarch64"

        if is_arm64:
            log.info("Skipping test case for %s, since it has not been published on ARM64", VmExtensionIds.GuestAgentDcrTestExtension)
        else:
            self.extension_install()




if __name__ == "__main__":
    ExtensionWorkflow.run_from_command_line()
