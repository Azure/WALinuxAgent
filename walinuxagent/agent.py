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
import walinuxagent.conf as conf
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.utils.shellutil as shellutil
import walinuxagent.protocol.detection as protocols
import walinuxagent.dhcphandler as dhcphandler

GuestAgentName = "WALinuxAgent"
GuestAgentLongName = "Microsoft Azure Linux Agent"
GuestAgentVersion = "WALinuxAgent-2.1.0-pre"

class Agent():

    def __init__(self):
        self.libDir = CurrOS.GetLibDir()
    
    def version(self):
        distro = CurrOS.CurrentDistroInfo;
        print "{0} running on {1} {2}".format(GuestAgentVersion, 
                                              distro[0], 
                                              distro[1])

    def deprovision(self, force=True, deluser=True):
        pass

    def run(self):
        self.savePid()

        if self.detectScvmmEnv():
            self.startScvmmAgent()
            return

        #Initialize 
        confPath = CurrOS.GetConfigurationPath() 
        config = conf.LoadConfiguration(confPath) 
        
        dhcpHandler = dhcphandler.DhcpHandler()
        dhcpHandler.probe()
        dhcpHandler.configNetwork()
    
        CurrOS.GenerateTransportCert()
        protocol = protocol.DetectDefaultProtocol()

        if config.getSwitch("Provisioning.Enabled"):
            ProvisionHandler(config, protocol).provision()
        
        #Start EnvMonitor
        #Activate resource disk
        #Set scsi disk timeout
        #Start load balancer

        #Handle state change
        while True:
            #Handle extensions
            #Report status
            
            #Wait for 25 seconds and detect protocol again.
            time.sleep(25)
            protocol = protocol.DetectDefaultProtocol()

    def detectScvmmEnv(self):
        return False

    def startScvmmAgent(self):
        pass

    def savePid(self):
        fileutil.SetFileContents(CurrOS.GetAgentPidPath(), str(os.getpid()))

