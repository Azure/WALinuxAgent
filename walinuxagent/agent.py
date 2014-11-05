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
import walinuxagent.utils.osutil as osutil
import walinuxagent.utils.shellutil as shellutil
import walinuxagent.protocol.detection as protocols

GuestAgentName = "WALinuxAgent"
GuestAgentLongName = "Microsoft Azure Linux Agent"
GuestAgentVersion = "WALinuxAgent-2.0.8"

class Agent():

    def version(self):
        distro = osutil.CurrentDistroInfo;
        print "{0} running on {1} {2}".format(GuestAgentVersion, 
                                              distro[0], 
                                              distro[1])

    def deprovision(self, force=True, deluser=True):
        pass

    def run(self):
        if self._detectScvmmEnv():
            return

        #Initialize 
        confPath = osutil.GetConfigurationPath() 
        config = conf.LoadConfiguration(confPath) 

        protocol = protocols.DetectEndpoint()
        if protocol is None:
            logger.Error("No available protocol detected.")
            return 
        if protocol.checkVersion():
            logger.Error("Protocol version check failed")
            return
        protocol.refreshCache()  

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
            time.sleep(25)
            protocol.refreshCache()

    def _detectScvmmEnv(self):
        return False

