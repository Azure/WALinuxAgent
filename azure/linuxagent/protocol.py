#!/usr/bin/env python
#
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

ProtocolV1File = os.path.join(LibDir, 'protocolv1')
ProtocolV2File = os.path.join(LibDir, 'protocolv2')

def DetectEndpoint():
    pass

def GetProtocol():
    if os.path.isfile(ProtocolV2File):
        return ProtocolV2()
    elif os.path.isfile(ProtocolV1File):
        return ProtocolV1()
    else:
        raise Exeption("Endpoint not detected")

class Protocol():

    def getVmInfo(self):
        pass

    def getCerts(self):
        pass

    def getExtensions(self):
        pass

    def getOvf(self):
        pass

    def reportProvisionStatus(self):
        pass

    def reportAgentStatus(self):
        pass

    def reportExtensionStatus(self):
        pass

    def reportEvent(self):
        pass

class ProtocolV1(Protocol):
    pass

class ProtocolV2(protocol):
    pass
