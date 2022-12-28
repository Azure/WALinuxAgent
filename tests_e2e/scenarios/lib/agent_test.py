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

from tests_e2e.scenarios.lib.agent_test_context import AgentTestContext
from tests_e2e.scenarios.lib.logging import log


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
        except:  # pylint: disable=bare-except
            log.exception("Test failed")
            sys.exit(1)

        sys.exit(0)


