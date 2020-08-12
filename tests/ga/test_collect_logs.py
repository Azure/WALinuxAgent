# Copyright 2020 Microsoft Corporation
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
import contextlib

from azurelinuxagent.common import logger
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, CollectLogsHandler
from azurelinuxagent.ga.periodic_operation import PeriodicOperation
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances


@contextlib.contextmanager
def _create_collect_logs_handler(enabled_operations=[], iterations=1):
    """
    Creates an instance of CollectLogsHandler that
        * Uses a mock_wire_protocol for network requests,
        * Executes only the operations given in the 'enabled_operations' parameter,
        * Runs its main loop only the number of times given in the 'iterations' parameter, and
        * Does not sleep at the end of each iteration

    The returned CollectLogsHandler is augmented with 2 methods:
        * get_mock_wire_protocol() - returns the mock protocol
        * run_and_wait() - invokes run() and wait() on the CollectLogsHandler

    """
    def run(self):
        if len(enabled_operations) == 0 or self._name in enabled_operations:
            run.original_definition(self)
    run.original_definition = PeriodicOperation.run

    with mock_wire_protocol(DATA_FILE) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.collect_logs.get_protocol_util", return_value=protocol_util):
            with patch.object(PeriodicOperation, "run", side_effect=run, autospec=True):
                with patch("azurelinuxagent.ga.collect_logs.CollectLogsHandler.stopped", side_effect=[False] * iterations + [True]):
                    with patch("time.sleep"):
                        def run_and_wait():
                            collect_logs_handler.run()
                            collect_logs_handler.join()

                        collect_logs_handler = get_collect_logs_handler()
                        collect_logs_handler.get_mock_wire_protocol = lambda: protocol
                        collect_logs_handler.run_and_wait = run_and_wait
                        yield collect_logs_handler


class TestCollectLogs(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        prefix = "UnitTest"
        logger.DEFAULT_LOGGER = Logger(prefix=prefix)

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_it_should_invoke_all_periodic_operations(self):
        invoked_operations = []

        with _create_collect_logs_handler() as collect_logs_handler:
            def mock_run(self):
                invoked_operations.append(self._name)

            with patch.object(PeriodicOperation, "run", side_effect=mock_run, spec=CollectLogsHandler.run):
                collect_logs_handler.run_and_wait()

                expected_operations = ["collect_and_send_logs"]

                self.assertEqual(invoked_operations.sort(), expected_operations.sort(),
                                 "The collect logs thread did not invoke the expected operations")
