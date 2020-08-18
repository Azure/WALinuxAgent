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
import os

from azurelinuxagent.common import logger
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, CollectLogsHandler
from azurelinuxagent.ga.periodic_operation import PeriodicOperation
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import Mock, MagicMock, patch, AgentTestCase, clear_singleton_instances, skip_if_predicate_true, \
    is_python_version_26


@contextlib.contextmanager
def _create_collect_logs_handler(iterations=1):
    """
    Creates an instance of CollectLogsHandler that
        * Uses a mock_wire_protocol for network requests,
        * Runs its main loop only the number of times given in the 'iterations' parameter, and
        * Does not sleep at the end of each iteration

    The returned CollectLogsHandler is augmented with 2 methods:
        * get_mock_wire_protocol() - returns the mock protocol
        * run_and_wait() - invokes run() and wait() on the CollectLogsHandler

    """
    with mock_wire_protocol(DATA_FILE) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.collect_logs.get_protocol_util", return_value=protocol_util):
            with patch("azurelinuxagent.ga.collect_logs.CollectLogsHandler.stopped", side_effect=[False] * iterations + [True]):
                with patch("time.sleep"):
                    with patch("azurelinuxagent.ga.collect_logs.os.path.exists", return_value=True):
                        with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs", return_value=True):
                            def run_and_wait():
                                collect_logs_handler.run()
                                collect_logs_handler.join()

                            collect_logs_handler = get_collect_logs_handler()
                            collect_logs_handler.get_mock_wire_protocol = lambda: protocol
                            collect_logs_handler.run_and_wait = run_and_wait
                            yield collect_logs_handler


@skip_if_predicate_true(is_python_version_26, "Disabled on Python 2.6")
class TestCollectLogs(AgentTestCase, HttpRequestPredicates):
    def setUp(self):
        AgentTestCase.setUp(self)
        prefix = "UnitTest"
        logger.DEFAULT_LOGGER = Logger(prefix=prefix)

        self.archive_path = os.path.join(self.tmp_dir, "logs.zip")
        self.mock_archive_path = patch("azurelinuxagent.ga.collect_logs.COMPRESSED_ARCHIVE_PATH", self.archive_path)
        self.mock_archive_path.start()

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def tearDown(self):
        if os.path.exists(self.archive_path):
            os.remove(self.archive_path)
        self.mock_archive_path.stop()
        AgentTestCase.tearDown(self)

    def _create_dummy_archive(self, size=1024):
        with open(self.archive_path, "wb") as f:
            f.truncate(size)

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

    @patch("azurelinuxagent.ga.collect_logs.CollectLogsHandler.collect_and_send_logs")
    def test_it_should_only_collect_logs_if_conditions_are_met(self, patch_collect_and_send_logs):
        # In order to collect logs, three conditions have to be met:
        # 1) the flag must be set in the conf file
        # 2) systemd must be managing services
        # 3) python version 2.7+ which is automatically true for these tests since they are disabled on py2.6

        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.os.path.exists", return_value=False):
                with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs", return_value=False):
                    collect_logs_handler.run_and_wait()

        self.assertEquals(patch_collect_and_send_logs.call_count, 0, "Log collection should not have been enabled")

        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.os.path.exists", return_value=True):
                with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs", return_value=False):
                    collect_logs_handler.run_and_wait()

        self.assertEquals(patch_collect_and_send_logs.call_count, 0, "Log collection should not have been enabled")

        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.os.path.exists", return_value=False):
                with patch("azurelinuxagent.ga.collect_logs.conf.get_collect_logs", return_value=True):
                    collect_logs_handler.run_and_wait()

        self.assertEquals(patch_collect_and_send_logs.call_count, 0, "Log collection should not have been enabled")

        with _create_collect_logs_handler() as collect_logs_handler:
            collect_logs_handler.run_and_wait()

        self.assertEquals(patch_collect_and_send_logs.call_count, 1, "Log collection should have been enabled")

    def test_log_collection_is_invoked_with_resource_limits(self):
        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.shellutil.run_command") as patch_run_command:
                collect_logs_handler.run_and_wait()

        args, kwargs = patch_run_command.call_args
        self.assertIn("systemd-run", args[0], "The log collector should have been invoked with systemd-run")
        self.assertIn("--property=CPUAccounting=1", args[0], "The log collector should have been invoked with CPUAccounting turned on")
        self.assertIn("--property=MemoryAccounting=1", args[0], "The log collector should have been invoked with MemoryAccounting turned on")
        self.assertIn("--property=CPUQuota=5%", args[0], "The log collector should have been invoked with a CPU limit")
        self.assertIn("--property=MemoryLimit=30M", args[0], "The log collector should have been invoked with a memory limit")

    def test_it_uploads_logs_when_collection_is_successful(self):
        archive_size = 42

        def mock_run_command(*_, **__):
            return self._create_dummy_archive(size=archive_size)

        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.shellutil.run_command", side_effect=mock_run_command):
                def http_put_handler(url, content, **__):
                    if self.is_host_plugin_put_logs_request(url):
                        http_put_handler.counter += 1
                        http_put_handler.archive = content
                        return MockHttpResponse(status=200)
                    return None

                http_put_handler.counter = 0
                http_put_handler.archive = b""
                protocol = collect_logs_handler.get_mock_wire_protocol()
                protocol.set_http_handlers(http_put_handler=http_put_handler)

                collect_logs_handler.run_and_wait()
                self.assertEquals(http_put_handler.counter, 1, "The PUT API to upload logs should have been called once")
                self.assertTrue(os.path.exists(self.archive_path), "The archive file should exist on disk")
                self.assertEquals(archive_size, len(http_put_handler.archive), "The archive file should have {0} bytes, not {1}".format(archive_size, len(http_put_handler.archive)))

    def test_it_does_not_upload_logs_when_collection_is_unsuccessful(self):
        with _create_collect_logs_handler() as collect_logs_handler:
            with patch("azurelinuxagent.ga.collect_logs.shellutil.run_command", side_effect=Exception("test exception")):
                def http_put_handler(url, _, **__):
                    if self.is_host_plugin_put_logs_request(url):
                        http_put_handler.counter += 1
                        return MockHttpResponse(status=200)
                    return None

                http_put_handler.counter = 0
                protocol = collect_logs_handler.get_mock_wire_protocol()
                protocol.set_http_handlers(http_put_handler=http_put_handler)

                collect_logs_handler.run_and_wait()
                self.assertTrue(os.path.exists(self.archive_path), "The archive file should exist on disk")
                self.assertEquals(http_put_handler.counter, 0, "The PUT API to upload logs shouldn't have been called")
