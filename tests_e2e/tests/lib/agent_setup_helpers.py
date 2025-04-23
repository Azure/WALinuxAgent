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
# Common helper functions for agent setup used by the tests
#
import time

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


def wait_for_agent_to_complete_provisioning(ssh_client: SshClient):
    """
    Wait for the agent to complete provisioning
    """
    log.info("Checking for the Agent to complete provisioning before starting the test validation")
    for _ in range(5):
        time.sleep(30)
        try:
            ssh_client.run_command("[ -f /var/lib/waagent/provisioned  ] && exit 0 || exit 1", use_sudo=True)
            break
        except CommandError:
            log.info("Waiting for agent to complete provisioning, will check again after a short delay")

    else:
        raise Exception("Timeout while waiting for the Agent to complete provisioning")
