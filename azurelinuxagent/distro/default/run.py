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
import time
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
from azurelinuxagent.metadata import GuestAgentLongName, GuestAgentVersion, \
                                     DistroName, DistroVersion, DistroFullName
import azurelinuxagent.protocol as prot
import azurelinuxagent.event as event
from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.utils.fileutil as fileutil


class RunHandler(object):
    def __init__(self, handlers):
        self.handlers = handlers

    def run(self):
        logger.Info("{0} Version:{1}", GuestAgentLongName, GuestAgentVersion) 
        logger.Info("OS: {0} {1}", DistroName, DistroVersion)

        event.EnableUnhandledErrorDump("Azure Linux Agent")
        fileutil.SetFileContents(OSUtil.GetAgentPidPath(), 
                                 str(os.getpid()))
        
        if self.handlers.scvmmHandler.detectScvmmEnv():
            return
        
        self.handlers.dhcpHandler.probe()

        prot.DetectDefaultProtocol()
        
        event.EventMonitor().startEventsLoop()

        self.handlers.provisionHandler.process()

        if conf.GetSwitch("ResourceDisk.Format", False):
            self.handlers.resourceDiskHandler.startActivateResourceDisk()
        
        self.handlers.envHandler.startMonitor()

        protocol = prot.Factory.getDefaultProtocol()
        while True:

            #Handle extensions
            handlerStatusList = self.handlers.extensionHandler.process()

            #Report status
            vmStatus = prot.VMStatus()
            vmStatus.vmAgent.agentVersion = GuestAgentLongName
            vmStatus.vmAgent.status = "Ready"
            vmStatus.vmAgent.message = "Guest Agent is running"
            for handlerStatus in handlerStatusList:
                vmStatus.extensionHandlers.append(handlerStatus)
            try:
                protocol.reportStatus(vmStatus)
            except prot.ProtocolError as e:
                logger.Error("Failed to report vm status: {0}", status)

            time.sleep(25)

