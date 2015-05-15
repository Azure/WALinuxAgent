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
import sys
import re
import shutil
import time
import traceback
import threading
import azureguestagent.logger as logger
import azureguestagent.conf as conf
from azureguestagent.osinfo import CurrOSInfo
from azureguestagent.handler import CurrOSHandlerFactory
from azureguestagent.utils.osutil import CurrOSUtil
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.fileutil as fileutil

GuestAgentName = "WALinuxAgent"
GuestAgentLongName = "Microsoft Azure Linux Agent"
GuestAgentVersion='2.1.0-pre'
GuestAgentLongVersion = "{0}-{1}".format(GuestAgentName, GuestAgentVersion)
GuestAgentAuthor='MS OSTC'
GuestAgentUri='https://github.com/Azure/WALinuxAgent'

class Agent(object):

    def __init__(self, config):
        self.config = config

    def run(self):
        self.initialize()
        self.start()

    def initialize(self):
        os.chdir(CurrOSUtil.GetLibDir())
        self.savePid()

        scvmmHandler = CurrOSHandlerFactory.GetScvmmHandler()
        if scvmmHandler.detectScvmmEnv():
            scvmmHandler.startScvmmAgent()
            return
        
        dhcpHandler = CurrOSHandlerFactory.GetDhcpHandler()
        dhcpHandler.waitForNetwork()
        dhcpHandler.probe()
        CurrOSUtil.SetWireServerEndpoint(dhcpHandler.getEndpoint())

        self.protocol = proto.DetectDefaultProtocol()

        provisoned = os.path.join(CurrOSUtil.GetLibDir(), "provisioned")
        if(not os.path.isfile(provisoned)):
            provisionHandler = provision.ProvisionHandler(self.config, 
                                                          self.protocol)
            try:
                provisionHandler.provision()
                fileutil.SetFileContents(provisoned, "")
            except Exception, e:
                self.protocol.reportAgentStatus(GuestAgentVersion, 
                                           "NotReady", 
                                           "ProvisioningFailed")
                raise e
       
        if self.config.getSwitch("ResourceDisk.Format", False):
            rdHandler = CurrOSHandlerFactory.GetResourceDiskHandler()
            rdHandler.startActivateResourceDisk(self.config)
        
        self.envmonitor = envmon.EnvMonitor(self.config, self.dhcpHandler)
        #TODO Start load balancer
        #Need to check whether this should be kept

    def start(self):
        #Handle state change
        while True:
            #Handle extensions
            extHandler = CurrOSHandlerFactory.GetExtensionHandler()
            extHandler.process(self.protocol)
            
            #Report status
            agentStatus = "Ready"
            agentStatusDetail = "Guest Agent is running"
            self.protocol.reportAgentStatus(GuestAgentVersion, 
                                            agentStatus,
                                            agentStatusDetail)
            time.sleep(25)
    
    def savePid(self):
        fileutil.SetFileContents(CurrOSUtil.GetAgentPidPath(), 
                                 str(os.getpid()))

def ParseArgs(sysArgv):
    cmd = None
    force = False
    verbose = False
    for a in sysArgv:
        if re.match("^([-/]*)deprovision\+user", a):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", a):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", a):
            cmd = "daemon"
        elif re.match("^([-/]*)version", a):
            cmd = "version"
        elif re.match("^([-/]*)serialconsole", a):
            cmd = "serialconsole" 
        elif re.match("^([-/]*)verbose", a):
            verbose = True
        elif re.match("^([-/]*)force", a):
            force = True
        elif re.match("^([-/]*)(help|usage|\?)", a):
            cmd = "help"
        else:
            cmd = "help"
    return cmd, force, verbose

def Version():
    print "{0} running on {1} {2}".format(GuestAgentLongVersion, 
                                          CurrOSInfo[0], 
                                          CurrOSInfo[1])
def Usage():
    print ("usage: {0} [-verbose] [-force] "
           "[-help|-deprovision[+user]|-version|-serialconsole|-daemon]")

def Main():
    command, force, verbose = ParseArgs(sys.argv[1:])
    if command == "deprovision+user":
        deprovisionHandler = CurrOSHandlerFactory.GetDeprovisionHandler()
        deprovisionHandler.deprovision(force=force, deluser=True)
    elif command == "deprovision":
        deprovisionHandler = CurrOSHandlerFactory.GetDeprovisionHandler()
        deprovisionHandler.deprovision(force=force, deluser=True)
    elif command == "daemon":
        configPath = CurrOSUtil.GetConfigurationPath()
        config = conf.LoadConfiguration(configPath)
        verbose = config.getSwitch("Logs.Verbose", False)
        logger.LoggerInit('/var/log/waagent.log', 
                          '/dev/console',
                          verbose=verbose)
        fileutil.CreateDir(CurrOSUtil.GetLibDir(), mode='0700')
        os.chdir(CurrOSUtil.GetLibDir())
        Agent(config).run()
    elif command == "serialconsole":
        #TODO
        pass
    elif command == "version":
        Version()
    else:
        Usage()
