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
from tests_e2e.tests.ext_cgroups.install_extensions import InstallExtensions
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log


class ExtCgroups(AgentVmTest):
    """
    This test verifies the installed extensions assigned correctly in their cgroups.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("=====Installing extensions to validate ext cgroups scenario")
        InstallExtensions(self._context).run()
        log.info("=====Executing remote script check_cgroups_extensions.py to validate extension cgroups")
        self._run_remote_test(self._ssh_client, "ext_cgroups-check_cgroups_extensions.py", use_sudo=True)
        log.info("Successfully verified that extensions present in correct cgroup")


if __name__ == "__main__":
    ExtCgroups.run_from_command_line()
