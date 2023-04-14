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
# BVT for RunCommand.
#
# Note that there are two incarnations of RunCommand (which are actually two different extensions):
# Microsoft.CPlat.Core.RunCommandHandlerLinux and Microsoft.CPlat.Core.RunCommandLinux. This test
# exercises both using the same strategy: execute the extension to create a file on the test VM,
# then fetch the contents of the file over SSH and compare against the known value.
#
import base64
import uuid

from assertpy import assert_that, soft_assertions
from typing import Callable, Dict

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.identifiers import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.vm_extension import VmExtension


class RunCommandBvt(AgentTest):
    class TestCase:
        def __init__(self, extension: VmExtension, get_settings: Callable[[str], Dict[str, str]]):
            self.extension = extension
            self.get_settings = get_settings

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        test_cases = [
            RunCommandBvt.TestCase(
                VmExtension(self._context.vm, VmExtensionIds.RunCommand, resource_name="RunCommand"),
                lambda s: {
                    "script": base64.standard_b64encode(bytearray(s, 'utf-8')).decode('utf-8')
                })
        ]

        if ssh_client.get_architecture() == "aarch64":
            log.info("Skipping test case for %s, since it has not been published on ARM64", VmExtensionIds.RunCommandHandler)
        else:
            test_cases.append(
                RunCommandBvt.TestCase(
                    VmExtension(self._context.vm, VmExtensionIds.RunCommandHandler, resource_name="RunCommandHandler"),
                    lambda s: {
                        "source": {
                            "script": s
                        }
                    }))

        with soft_assertions():
            for t in test_cases:
                log.info("Test case: %s", t.extension)

                unique = str(uuid.uuid4())
                test_file = f"/tmp/waagent-test.{unique}"
                script = f"echo '{unique}' > {test_file}"
                log.info("Script to execute: %s", script)

                t.extension.enable(settings=t.get_settings(script))
                t.extension.assert_instance_view()

                log.info("Verifying contents of the file created by the extension")
                contents = ssh_client.run_command(f"cat {test_file}").rstrip()  # remove the \n
                assert_that(contents).\
                    described_as("Contents of the file created by the extension").\
                    is_equal_to(unique)
                log.info("The contents match")


if __name__ == "__main__":
    RunCommandBvt.run_from_command_line()
