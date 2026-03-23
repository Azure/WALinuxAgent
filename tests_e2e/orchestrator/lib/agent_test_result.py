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
import datetime
import traceback
import uuid

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
from lisa import notifier  # pylint: disable=E0401
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401

from typing import Optional

from azurelinuxagent.common.future import UTC


class AgentTestResultMessage(TestResultMessage):
    def __init__(self, suite_name: str, test_name: str, status: TestStatus):
        super().__init__()
        self.type: str = "AgentTestResultMessage"
        self.id_: str = str(uuid.uuid4())
        self.status: TestStatus = status
        self.suite_full_name: str = suite_name
        self.suite_name: str = suite_name
        self.full_name: str = test_name
        self.name: str = test_name
        self.elapsed: float = 0
        self.message: str = ""
        self.stacktrace: Optional[str] = None


class AgentTestResult:
    @staticmethod
    def report(
            suite_name: str,
            test_name: str,
            status: TestStatus,
            start_time: datetime.datetime,
            message: str = "",
            add_exception_stack_trace: bool = False
    ) -> None:
        """
        Reports a test result to the junit notifier
        """
        # The junit notifier requires an initial RUNNING message in order to register the test in its internal cache.
        msg: AgentTestResultMessage = AgentTestResultMessage(suite_name, test_name, TestStatus.RUNNING)

        notifier.notify(msg)

        # Now send the actual result. The notifier pipeline makes a deep copy of the message so it is OK to re-use the
        # same object and just update a few fields. If using a different object, be sure that the "id_" is the same.
        msg.status = status
        msg.message = message
        if add_exception_stack_trace:
            msg.stacktrace = traceback.format_exc()
        msg.elapsed = (datetime.datetime.now(UTC) - start_time).total_seconds()

        notifier.notify(msg)
