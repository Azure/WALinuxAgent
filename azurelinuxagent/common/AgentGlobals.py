# Microsoft Azure Linux Agent
#
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


class AgentGlobals(object):
    """
    This class is used for setting AgentGlobals which can be used all throughout the Agent.
    """

    GUID_ZERO = "00000000-0000-0000-0000-000000000000"

    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    _container_id = GUID_ZERO

    #
    # The telemetry modules require the information about whether the agent is running in a CVM or not. This variable
    # will be updated when the CVM info is initialized in ConfidentialVMInfo. There are three possible values:
    #   - None
    #   - True
    #   - False
    # The value is None when the CVM info has not yet been initialized.
    #
    _is_cvm = None

    @staticmethod
    def get_container_id():
        return AgentGlobals._container_id

    @staticmethod
    def update_container_id(container_id):
        AgentGlobals._container_id = container_id

    @staticmethod
    def get_is_cvm():
        # The value of _is_cvm is uninitialized until ConfidentialVMInfo.fetch_and_initialize_cvm_info() is called. The value
        # is only initialized on the ExtHandler process, since fetching the CVM info requires an extra network call and the value 
        # is not needed on the Daemon or LogCollector processes. 
        # If this method is called before the value is initialized, raise an exception.
        if AgentGlobals._is_cvm is None:
            raise Exception("CVM info has not been initialized yet")
        return AgentGlobals._is_cvm

    @staticmethod
    def update_is_cvm(is_cvm):
        AgentGlobals._is_cvm = is_cvm
