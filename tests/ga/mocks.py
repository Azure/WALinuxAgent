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

from mock import PropertyMock

from azurelinuxagent.ga.agent_update import AgentUpdateHandler
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler
from azurelinuxagent.ga.remoteaccess import RemoteAccessHandler
from azurelinuxagent.ga.update import UpdateHandler, get_update_handler
from tests.tools import patch, Mock, mock_sleep


@contextlib.contextmanager
def mock_update_handler(protocol,
                        iterations=1,
                        on_new_iteration=lambda _: None,
                        exthandlers_handler=None,
                        remote_access_handler=None,
                        agent_update_handler=None,
                        autoupdate_enabled=False,
                        check_daemon_running=False,
                        start_background_threads=False,
                        check_background_threads=False
                        ):
    """
    Creates a mock UpdateHandler that executes its main loop for the given 'iterations'.
        * If 'on_new_iteration' is given, it is invoked at the beginning of each iteration passing the iteration number as argument.
        * Network requests (e.g. requests for the goal state) are done using the given 'protocol'.
        * The mock UpdateHandler uses mock no-op ExtHandlersHandler and RemoteAccessHandler, unless they are given by 'exthandlers_handler' and 'remote_access_handler'.
        * Agent updates are disabled, unless specified otherwise by 'autoupdate_enabled'.
        * The check for the daemon is skipped, unless specified otherwise by 'check_daemon_running'
        * Background threads (monitor, env, telemetry, etc) are not started, unless specified otherwise by 'start_background_threads'
        * The check for background threads is skipped, unless specified otherwise by 'check_background_threads'
        * The UpdateHandler is augmented with these extra functions:
              * get_exit_code() - returns the code passed to sys.exit() when the handler exits
              * get_iterations() - returns the number of iterations executed by the main loop
              * get_iterations_completed() - returns the number of iterations of the main loop that completed execution (i.e. were not interrupted by an exception, return, etc)
    """
    iteration_count = [0]

    def is_running(*args):  # mock for property UpdateHandler.is_running, which controls the main loop
        if len(args) == 0:
            # getter
            enter_loop = iteration_count[0] < iterations
            if enter_loop:
                iteration_count[0] += 1
                on_new_iteration(iteration_count[0])
            return enter_loop
        else:
            # setter
            return None

    if exthandlers_handler is None:
        exthandlers_handler = ExtHandlersHandler(protocol)
    else:
        exthandlers_handler.protocol = protocol

    if remote_access_handler is None:
        remote_access_handler = RemoteAccessHandler(protocol)

    if agent_update_handler is None:
        agent_update_handler = AgentUpdateHandler(protocol)

    cleanup_functions = []

    def patch_object(target, attribute):
        p = patch.object(target, attribute)
        p.start()
        cleanup_functions.insert(0, p.stop)

    try:
        with patch("azurelinuxagent.ga.exthandlers.get_exthandlers_handler", return_value=exthandlers_handler):
            with patch("azurelinuxagent.ga.agent_update.get_agent_update_handler", return_value=agent_update_handler):
                with patch("azurelinuxagent.ga.remoteaccess.get_remote_access_handler", return_value=remote_access_handler):
                    with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=autoupdate_enabled):
                        with patch.object(UpdateHandler, "is_running", PropertyMock(side_effect=is_running)):
                            with patch('azurelinuxagent.ga.update.time.sleep', side_effect=lambda _: mock_sleep(0.001)) as sleep:
                                with patch('sys.exit', side_effect=lambda _: 0) as mock_exit:
                                    if not check_daemon_running:
                                        patch_object(UpdateHandler, "_check_daemon_running")
                                    if not start_background_threads:
                                        patch_object(UpdateHandler, "_start_threads")
                                    if not check_background_threads:
                                        patch_object(UpdateHandler, "_check_threads_running")

                                    def get_exit_code():
                                        if mock_exit.call_count == 0:
                                            raise Exception("The UpdateHandler did not exit")
                                        if mock_exit.call_count != 1:
                                            raise Exception("The UpdateHandler exited multiple times ({0})".format(mock_exit.call_count))
                                        args, _ = mock_exit.call_args
                                        return args[0]

                                    def get_iterations():
                                        return iteration_count[0]

                                    def get_iterations_completed():
                                        return sleep.call_count

                                    update_handler = get_update_handler()
                                    update_handler.protocol_util.get_protocol = Mock(return_value=protocol)
                                    update_handler.get_exit_code = get_exit_code
                                    update_handler.get_iterations = get_iterations
                                    update_handler.get_iterations_completed = get_iterations_completed

                                    yield update_handler
    finally:
        for f in cleanup_functions:
            f()

