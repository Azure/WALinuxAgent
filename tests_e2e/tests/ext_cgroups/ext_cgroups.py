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

from tests_e2e.tests.lib.agent_test import AgentTest
from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log


class ExtCgroups(AgentTest):
    """
    This test verifies the installed extensions assigned correctly in their cgroups.
    """

    def __init__(self, context: AgentTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()

    def run(self):
        log.info("=====Validating extension cgroups=====")
        result = self._ssh_client.run_command("ext_cgroups-check_cgroups_extensions.py", use_sudo=True)
        log.info(result)
        log.info("=====Verified that extensions present in correct cgroup=====")


if __name__ == "__main__":
    ExtCgroups.run_from_command_line()