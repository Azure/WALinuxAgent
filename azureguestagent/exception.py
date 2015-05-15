# Windows Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

"""
Base class of agent error.
"""
class AgentError(Exception):
    def __init__(self, errno, msg):
        msg = "({0}){1}".format(errno, msg)
        super(AgentError, self).__init__(msg)

"""
When configure file is not found or malformed.
"""
class AgentConfigError(AgentError):
    def __init__(self, msg):
        super(AgentConfigError, self).__init__('000001', msg)

"""
When network is not avaiable.
"""
class AgentNetworkError(AgentError):
    def __init__(self, msg):
        super(AgentNetworkError, self).__init__('000002', msg)

"""
When failed to execute an extension
"""
class ExtensionError(AgentError):
    def __init__(self, msg):
        super(ExtensionError, self).__init__('000003', msg)

