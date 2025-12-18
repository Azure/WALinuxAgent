#!/usr/bin/env pypy3

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

from tests_e2e.tests.lib.logging import log, indent
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.test_result import TestSkipped


class FirewallUtilities:
    @staticmethod
    def skip_test_if_proxy_agent_is_managing_the_wireserver_endpoint(ssh_client: SshClient):
        """
        Raises TestSkipped if the proxy agent is managing the wireserver endpoint.

        If this is the case, the HTTP requests to the WireServer are blocked by the Proxy Agent and they do not reach the firewall endpoint,
        so the firewall tests are not applicable.
        """
        try:
            stdout = ssh_client.run_command("is-proxy-agent-active.py")
            log.info(f"Detected the Proxy Agent\n{indent(stdout)}")
            raise TestSkipped("The Proxy Agent is managing the WireServer endpoint so firewall rules are not applicable.")
        except CommandError as e:
            if e.exit_code == 1:
                log.info(f"The Proxy Agent is not managing the WireServer endpoint.\n{indent(str(e.stdout))}")
            else:
                raise
