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

GuestAgentName = "WALinuxAgent"
GuestAgentLongName = "Windows Azure Linux Agent"
GuestAgentVersion = "WALinuxAgent-2.0.8"
#WARNING this value is used to confirm the correct fabric protocol.
ProtocolVersion = "2012-11-30" 

class Agent():
    def run(self):
        pass
