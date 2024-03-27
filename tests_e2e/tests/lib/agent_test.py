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
from datetime import datetime

from assertpy import fail
from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test_context import AgentTestContext, AgentVmTestContext, AgentVmssTestContext
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
    Abstract base class for Agent tests
    """
    def __init__(self, context: AgentTestContext):
        self._context: AgentTestContext = context

    @abstractmethod
    def run(self):
        """
        Test must define this method, which is used to execute the test.
        """

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        """
        Tests can override this method to return a list with rules to ignore errors in the agent log (see agent_log.py for sample rules).
        """
        return []

    def get_ignore_errors_before_timestamp(self) -> datetime:
        # Ignore errors in the agent log before this timestamp
        return datetime.min

    @classmethod
    def run_from_command_line(cls):
        """
        Convenience method to execute the test when it is being invoked directly from the command line (as opposed as
        being invoked from a test framework or library.)

        TODO: Need to implement for reading test specific arguments from command line
        """
        try:
            if issubclass(cls, AgentVmTest):
                cls(AgentVmTestContext.from_args()).run()
            elif issubclass(cls, AgentVmssTest):
                cls(AgentVmssTestContext.from_args()).run()
            else:
                raise Exception(f"Class {cls.__name__} is not a valid test class")
        except SystemExit:  # Bad arguments
            pass
        except AssertionError as e:
            log.error("%s", e)
            sys.exit(1)
        except:  # pylint: disable=bare-except
            log.exception("Test failed")
            sys.exit(1)

        sys.exit(0)

    def _run_remote_test(self, ssh_client: SshClient, command: str, use_sudo: bool = False, attempts: int = ATTEMPTS, attempt_delay: int = ATTEMPT_DELAY) -> None:
        """
        Derived classes can use this method to execute a remote test (a test that runs over SSH).
        """
        try:
            output = ssh_client.run_command(command=command, use_sudo=use_sudo, attempts=attempts, attempt_delay=attempt_delay)
            log.info("*** PASSED: [%s]\n%s", command, self._indent(output))
        except CommandError as error:
            if error.exit_code == FAIL_EXIT_CODE:
                fail(f"[{command}] {error.stderr}{self._indent(error.stdout)}")
            raise RemoteTestError(command=error.command, exit_code=error.exit_code, stdout=self._indent(error.stdout), stderr=error.stderr)

    @staticmethod
    def _indent(text: str, indent: str = " " * 8):
        return "\n".join(f"{indent}{line}" for line in text.splitlines())


class AgentVmTest(AgentTest):
    """
    Base class for Agent tests that run on a single VM
    """


class AgentVmssTest(AgentTest):
    """
    Base class for Agent tests that run on a scale set
    """

