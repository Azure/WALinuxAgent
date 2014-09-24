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

from azure.linuxagent.util import *
from azure.linuxagent.logger import *

__ProtocolV1FilePath = os.path.join(LibDir, 'protocolv1')
__ProtocolV2FilePath = os.path.join(LibDir, 'protocolv2')

__SleepDurations = [0, 10, 30, 60, 60]

def DetectEndpoint():
    detected = False
    for duration in __SleepDurations:
        Log("Detect endpoint...")
        OpenPortForDhcp()
        if(_DetectEndpoint()):
            detected = True
            break
        sleep(duration)
        RestartNetwork()

    if not detected:
        raise Exception("Detect endpoint failed.") 

def _DetectEndpoint():
    metadataServer = DetectMetadataServer()
    if metadataServer:
        SetFileContent(__ProtocolV2FilePath, '')
        return True
    else:
        os.remove(__ProtocolV2FilePath)

    wireServer = DetectWireServer()
    if wireServer:
        SetFileContent(__ProtocolV1FilePath, wireServer)
        return True
    else:
        os.remove(__ProtocolV1FilePath)

    return False

__MeatadataServerAddr=''
def DetectMetadataServer():
    pass

def DetectWireServer():
    pass

def GetProtocol():
    if os.path.isfile(__ProtocolV2FilePath):
        return ProtocolV2()
    elif os.path.isfile(__ProtocolV1FilePath):
        wireServer = GetFileContent(__ProtocolV1FilePath)
        return ProtocolV1(wireServer)
    else:
        raise Exeption("Endpoint not detected")

class ProtocolV1(Protocol):

    def __init__(self, endpoint):
        self.endpoint = endpoint

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

class ProtocolV2(protocol):

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

