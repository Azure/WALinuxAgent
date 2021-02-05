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

    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    _container_id = "00000000-0000-0000-0000-000000000000"

    @staticmethod
    def get_container_id():
        return AgentGlobals._container_id

    @staticmethod
    def update_container_id(container_id):
        AgentGlobals._container_id = container_id
