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
import traceback
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import CurrOS, CurrOSInfo
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.dhcphandler as dhcphandler
from azurelinuxagent.protocol.common import *
from azurelinuxagent.protocol.v1 import ProtocolV1
from azurelinuxagent.protocol.v2 import ProtocolV2

"""
This routine tries to detect protocol endpoint to deteminate which version of
protocol is used. It also tries to fix network issue while retrying.

It will call Detect() defined by protocol classes passed by param one by one, 
until a valid protocol endpoint is detected.
"""

__Protocols = [ProtocolV2, ProtocolV1]

def DetectAvailableProtocols(protocols=__Protocols):
    libDir = CurrOS.GetLibDir()
    availableProtocols = []
    for protocol in protocols:
        logger.Info("Detect available protocols...")
        protocolFilePath = os.path.join(libDir, protocol.__name__)
        if os.path.isfile(protocolFilePath):
            os.remove(protocolFilePath)
        try:
            detected = protocol.Detect()
            fileutil.SetFileContents(protocolFilePath, '')
            logger.Info("Detecting protocol: {0}", protocol.__name__)
            availableProtocols.append(detected)
            break
        except ProtocolNotFound:
            logger.Warn("{0} is not available.", protocol.__name__)
    return availableProtocols

def DetectDefaultProtocol(protocols=__Protocols):
    availableProtocols = DetectAvailableProtocols(protocols)
    return ChooseDefaultProtocol(availableProtocols)

def ChooseDefaultProtocol(availableProtocols):
    if len(availableProtocols) > 0:
        return availableProtocols[-1]
    else:
        raise ProtocolNotFound("No available protocol detected.")

"""
This routine will check 'ProtocolV*' file under lib dir. If detected, It will call
Init() defined by protocol classes passed by param and return.

Please note this method must be called after DetectAvailableProtocols is called 
and a valid protocol endpoint was detected.

Agent will call DetectAvailableProtocols periodically
"""
def GetAvailableProtocols(protocols=__Protocols):
    libDir = CurrOS.GetLibDir()
    availableProtocols = []
    for protocol in protocols:
        protocolFilePath = os.path.join(libDir, protocol.__name__)
        if os.path.isfile(protocolFilePath):
            availableProtocol = protocol.Init()
            availableProtocols.append(availableProtocol)
    return availableProtocols

def GetDefaultProtocol(protocols=__Protocols):
    availableProtocols = GetAvailableProtocols(protocols)
    return ChooseDefaultProtocol(availableProtocols)

