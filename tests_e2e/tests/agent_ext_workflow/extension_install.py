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

from assertpy import assert_that, soft_assertions
from typing import Callable, Dict

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.vm_extension import VmExtension


class ExtensionInstall(AgentTest):
    class GuestAgentDcrTestExtension:
        COUNT_KEY_NAME = "Count"
        NAME_KEY_NAME = "name"

        def __init__(self, extension: VmExtension):
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
            self.message = settings

        def assert_instance_view(self):
            self.extension.assert_instance_view(expected_version=self.version, expected_message=self.message)

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        is_arm64: bool = ssh_client.get_architecture() == "aarch64"

        # create extension abstraction
        dcr_test_ext_id = VmExtensionIdentifier(VmExtensionIds.GuestAgentDcrTestExtension.publisher, VmExtensionIds.GuestAgentDcrTestExtension.type, "1.1")
        dcr_test_ext = VmExtension(
            self._context.vm,
            dcr_test_ext_id,
            resource_name="GuestAgentDcr-TestInstall")
        dcr_ext = ExtensionInstall.GuestAgentDcrTestExtension(extension=dcr_test_ext)

        if is_arm64:
            log.info("Skipping test case for %s, since it has not been published on ARM64", VmExtensionIds.GuestAgentDcrTestExtension)
        else:
            log.info("Installing %s", dcr_test_ext)

            dcr_ext.modify_ext_settings_and_enable()
            dcr_ext.assert_instance_view()

            # setting_name = "%s-%s, %s: %s" % (dcr_test_ext_id.type, version, self.COUNT_KEY_NAME, self.enable_count)
            # dcr_test_ext.enable(
            #     settings={
            #         'name': ''
            #     },
            #     auto_upgrade_minor_version=False
            # )
            # custom_script_2_0.assert_instance_view(expected_version="2.0", expected_message=message)
            #
            # custom_script_2_1 = VmExtension(
            #     self._context.vm,
            #     VmExtensionIdentifier(VmExtensionIds.CustomScript.publisher, VmExtensionIds.CustomScript.type, "2.1"),
            #     resource_name="CustomScript")
            #
            # if is_arm64:
            #     log.info("Installing %s", custom_script_2_1)
            # else:
            #     log.info("Updating %s to %s", custom_script_2_0, custom_script_2_1)
            #
            # message = f"Hello {uuid.uuid4()}!"
            # custom_script_2_1.enable(
            #     settings={
            #         'commandToExecute': f"echo \'{message}\'"
            #     }
            # )
            # custom_script_2_1.assert_instance_view(expected_version="2.1", expected_message=message)
            #
            # custom_script_2_1.delete()
            #
            # assert_that(custom_script_2_1.get_instance_view). \
            #     described_as("Fetching the instance view should fail after removing the extension"). \
            #     raises(ResourceNotFoundError)


if __name__ == "__main__":
    ExtensionInstall.run_from_command_line()
