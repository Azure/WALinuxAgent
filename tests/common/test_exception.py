# Copyright 2019 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import sys, inspect # pylint: disable=multiple-imports
from azurelinuxagent.common.exception import AgentError
from tests.tools import AgentTestCase


class TestAgentError(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        cls.agent_exceptions = inspect.getmembers(
            sys.modules["azurelinuxagent.common.exception"],
            lambda member: inspect.isclass(member) and issubclass(member, AgentError))

    def test_agent_exceptions_should_set_their_error_message(self):
        for exception_name, exception_class in TestAgentError.agent_exceptions:
            exception_instance = exception_class("A test Message")

            self.assertEqual("[{0}] A test Message".format(exception_name), str(exception_instance))

    def test_agent_exceptions_should_include_the_inner_exception_in_their_error_message(self):
        inner_exception = Exception("The inner exception")

        for exception_name, exception_class in TestAgentError.agent_exceptions:
            exception_instance = exception_class("A test Message", inner_exception)

            self.assertEqual("[{0}] A test Message\nInner error: The inner exception".format(exception_name), str(exception_instance))
