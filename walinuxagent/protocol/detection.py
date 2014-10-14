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
import os
import walinuxagent.logger as logger
import walinuxagent.utils.osutil as osutil
import walinuxagent.utils.fileutil as fileutil
from walinuxagent.protocol.v1 import ProtocolV1
from walinuxagent.protocol.v2 import ProtocolV2

"""
This routine tries to detect protocol endpoint to deteminate which version of
protocol is used. It also tries to fix network issue while retrying.

It will call Detect() defined by protocol classes passed by param one by one, 
until a valid protocol endpoint is detected.
"""

__Protocols = [ProtocolV2, ProtocolV1]
__SleepDurations = [0, 10, 30, 60, 60]

def DetectEndpoint(protocols=__Protocols, libDir=osutil.LibDir, 
                   sleepDurations=__SleepDurations):
    for duration in sleepDurations:
        logger.Info("Detect endpoint...")
        for protocol in protocols:
            protocolFilePath = os.path.join(libDir, protocol.__name__)
            if protocol.Detect():
                fileutil.SetFileContents(protocolFilePath, '')
                return
            elif os.path.isfile(protocolFilePath):
                os.remove(protocolFilePath)
        sleep(duration)
        osutil.RestartNetwork()

#TODO report event
    raise Exception("Detect endpoint failed.") 

"""
This routine will check 'ProtocolV*' file under lib dir. If detected, It will call
Init() defined by protocol classes passed by param and return.

Please note this method must be called after DetectEndpoint is called and a valid
protocol endpoint was detected.

Agent will call DetectEndpoint on start. 
"""
def GetProtocol(protocols=__Protocols, libDir=osutil.LibDir):
    for protocol in protocols:
        protocolFilePath = os.path.join(libDir, protocol.__name__)
        if os.path.isfile(protocolFilePath):
            return protocol.Init()

#TODO report event
    raise Exeption("Endpoint not detected")

