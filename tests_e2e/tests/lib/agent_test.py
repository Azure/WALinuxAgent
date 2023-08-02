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

import sys

from abc import ABC, abstractmethod
from assertpy import fail
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test_context import AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import FAIL_EXIT_CODE
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import ATTEMPTS, ATTEMPT_DELAY, SshClient


class TestSkipped(Exception):
    """
    Tests can raise this exception to indicate they should not be executed (for example, if trying to execute them on
    an unsupported distro
    """


class RemoteTestError(CommandError):
    """
    Raised when a remote test fails with an unexpected error.
    """


class AgentTest(ABC):
    """
    Defines the interface for agent tests, which are simply constructed from an AgentTestContext and expose a single method,
    run(), to execute the test.
    """
    def __init__(self, context: AgentTestContext):
        self._context = context

    @abstractmethod
    def run(self):
        pass

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        # Tests can override this method to return a list with rules to ignore errors in the agent log (see agent_log.py for sample rules).
        return []

    @classmethod
    def run_from_command_line(cls):
        """
        Convenience method to execute the test when it is being invoked directly from the command line (as opposed as
        being invoked from a test framework or library.
        """
        try:
            cls(AgentTestContext.from_args()).run()
        except SystemExit:  # Bad arguments
            pass
        except AssertionError as e:
            log.error("%s", e)
            sys.exit(1)
        except:  # pylint: disable=bare-except
            log.exception("Test failed")
            sys.exit(1)

        sys.exit(0)

    def _run_remote_test(self, command: str, use_sudo: bool = False, attempts: int = ATTEMPTS, attempt_delay: int = ATTEMPT_DELAY) -> None:
        """
        Derived classes can use this method to execute a remote test (a test that runs over SSH).
        """
        try:
            ssh_client: SshClient = self._context.create_ssh_client()
            output = ssh_client.run_command(command=command, use_sudo=use_sudo, attempts=attempts, attempt_delay=attempt_delay)
            log.info("*** PASSED: [%s]\n%s", command, self._indent(output))
        except CommandError as error:
            if error.exit_code == FAIL_EXIT_CODE:
                fail(f"[{command}] {error.stderr}{self._indent(error.stdout)}")
            raise RemoteTestError(command=error.command, exit_code=error.exit_code, stdout=self._indent(error.stdout), stderr=error.stderr)

    @staticmethod
    def _indent(text: str, indent: str = " " * 8):
        return "\n".join(f"{indent}{line}" for line in text.splitlines())
