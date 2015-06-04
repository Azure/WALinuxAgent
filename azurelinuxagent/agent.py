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
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
import azurelinuxagent.protocol as prot
from azurelinuxagent.osinfo import CurrOSInfo
from azurelinuxagent.handler import CurrOSHandlerFactory
from azurelinuxagent.utils.osutil import CurrOSUtil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil

GuestAgentName = "WALinuxAgent"
GuestAgentVersion='2.1.0-pre'
GuestAgentLongVersion = "{0}-{1}".format(GuestAgentName, GuestAgentVersion)

def Init():
    #Init config
    configPath = CurrOSUtil.GetConfigurationPath()
    conf.LoadConfiguration(configPath)
    
    #Init log
    verbose = conf.GetSwitch("Logs.Verbose", False)
    logger.LoggerInit('/var/log/waagent.log', '/dev/console', verbose=verbose)
    
    #Create lib dir
    fileutil.CreateDir(CurrOSUtil.GetLibDir(), mode='0700')
    os.chdir(CurrOSUtil.GetLibDir())

def Run():
    fileutil.SetFileContents(CurrOSUtil.GetAgentPidPath(), 
                             str(os.getpid()))

    scvmmHandler = CurrOSHandlerFactory.GetScvmmHandler()
    if scvmmHandler.detectScvmmEnv():
        scvmmHandler.startScvmmAgent()
        return
    
    dhcpHandler = CurrOSHandlerFactory.GetDhcpHandler()
    dhcpHandler.probe()

    prot.DetectDefaultProtocol()
    
    provisionHandler = CurrOSHandlerFactory.getProvisionHandler()
    provisionHandler.process()

    if conf.getSwitch("ResourceDisk.Format", False):
        rdHandler = CurrOSHandlerFactory.GetResourceDiskHandler()
        rdHandler.startActivateResourceDisk()
    
    envHandler = CurrOSHandlerFactory.GetEnvHandler()
    envHandler.startMonitor()

    #TODO Start load balancer
    #Need to check whether this should be kept

    protocol = prot.GetDefaultProtocol()
    while True:
        #Handle extensions
        extHandler = CurrOSHandlerFactory.GetExtensionHandler()
        extHandler.process()
        
        #Report status
        agentStatus = "Ready"
        agentStatusDetail = "Guest Agent is running"
        protocol.reportAgentStatus(GuestAgentVersion, 
                                   agentStatus,
                                   agentStatusDetail)
        time.sleep(25)

def Deprovision(force=False, deluser=False):
    deprovisionHandler = CurrOSHandlerFactory.GetDeprovisionHandler()
    deprovisionHandler.deprovision(force=force, deluser=deluser)
        
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
        elif re.match("^([-/]*)run", a):
            cmd = "run"
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
    print (("usage: {0} [-verbose] [-force] "
            "[-help|-deprovision[+user]|-version|-serialconsole|-daemon|-run]"
            "").format(sys.argv[0]))

def Daemon():
    print "Start daemon in backgroud"
    subprocess.Popen([sys.argv[0], "run"], stdout=devnull, stderr=devnull)

def Main():
    command, force, verbose = ParseArgs(sys.argv[1:])
    if command == "version":
        Version()
    elif command == "help":
        Usage()
    elif command == "daemon":
        Daemon()
    else: 
        Init()
        if command == "serialconsole":
            #TODO
            pass
        if command == "deprovision+user":
            Deprovision(force, deluser=True)
        elif command == "deprovision":
            Deprovision(force, deluser=False)
        elif command == "run":
            Run()
