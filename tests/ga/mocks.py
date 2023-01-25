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
# Requires Python 2.6+ and Openssl 1.0+
#

import contextlib

try:
    from unittest.mock import PropertyMock
except ImportError:
    from mock import PropertyMock
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler
from azurelinuxagent.ga.update import UpdateHandler, get_update_handler
from tests.tools import patch, Mock, mock_sleep


@contextlib.contextmanager
def mock_update_handler(protocol, iterations=1, on_new_iteration=lambda _: None, exthandlers_handler=None, remote_access_handler=None, enable_agent_updates=False):
    """
    Creates a mock UpdateHandler that executes its main loop for the given 'iterations'.
    If 'on_new_iteration' is given, it is invoked at the beginning of each iteration passing the iteration number as argument.
    Network requests (e.g. requests for the goal state) are done using the given 'protocol'.
    The mock UpdateHandler uses mock no-op ExtHandlersHandler and RemoteAccessHandler, unless they are given by 'exthandlers_handler' and 'remote_access_handler'.
    Agent updates are disabled, unless specified otherwise with 'enable_agent_updates'.
    Background threads (monitor, env, telemetry, etc) are not started.
    """
    iteration_count = [0]

    def is_running(*args):  # mock for property UpdateHandler.is_running, which controls the main loop
        if len(args) == 0:
            # getter
            iteration_count[0] += 1
            on_new_iteration(iteration_count[0])
            return iteration_count[0] <= iterations
        else:
            # setter
            return None

    if exthandlers_handler is None:
        exthandlers_handler = ExtHandlersHandler(protocol)

    if remote_access_handler is None:
        remote_access_handler = RemoteAccessHandler(protocol)

    with patch("azurelinuxagent.ga.exthandlers.get_exthandlers_handler", return_value=exthandlers_handler):
        with patch("azurelinuxagent.ga.remoteaccess.get_remote_access_handler", return_value=remote_access_handler):
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=enable_agent_updates):
                with patch.object(UpdateHandler, "is_running", PropertyMock(side_effect=is_running)):
                    with patch.object(UpdateHandler, "_check_daemon_running"):
                        with patch.object(UpdateHandler, "_start_threads"):
                            with patch.object(UpdateHandler, "_check_threads_running"):
                                with patch('time.sleep', side_effect=lambda _: mock_sleep(0.001)):
                                    with patch('sys.exit', side_effect=lambda _: 0):
                                        update_handler = get_update_handler()
                                        update_handler.protocol_util.get_protocol = Mock(return_value=protocol)

                                        yield update_handler

