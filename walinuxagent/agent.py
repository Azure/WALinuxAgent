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
import shutil
import walinuxagent.logger as logger
import walinuxagent.conf as conf
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.utils.shellutil as shellutil
import walinuxagent.protocol.detection as protocols
import walinuxagent.dhcphandler as dhcphandler
import walinuxagent.envmonitor as envmon
import walinuxagent.extension as ext

GuestAgentName = "WALinuxAgent"
GuestAgentLongName = "Microsoft Azure Linux Agent"
GuestAgentVersion = "WALinuxAgent-2.1.0-pre"
VmmConfigFileName = "linuxosconfiguration.xml"
VmmStartupScriptName= "install"
DataLossWarningFile="DATALOSS_WARNING_README.txt"
DataLossWarning="""\
WARNING: THIS IS A TEMPORARY DISK. 

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at : http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""

class Agent():

    def __init__(self, config):
        self.config = config

    def run(self):
        self.savePid()

        if self.detectScvmmEnv():
            self.startScvmmAgent()
            return
       
        #Intialize
        self.waitForNetwork()

        self.dhcpHandler = dhcphandler.DhcpHandler()
        self.dhcpHandler.probe()

        self.envmonitor = envmon.EnvMonitor(self.config, self.dhcpHandler)
        self.protocol = protocol.DetectDefaultProtocol()

        provisoned = os.path.join(CurrOS.GetLibDir(), "provisioned")
        if(not os.path.isfile(provisoned)):
            provisionHandler = ProvisionHandler(self.config, 
                                                self.protocol, 
                                                self.envmonitor)
            try:
                provisionHandler.provision()
                fileutil.SetFileContents(provisoned)
            except Exception, e:
                protocol.reportAgentStatus(GuestAgentVersion, 
                                           "NotReady", 
                                           "ProvisioningFailed")
                raise e
       
        if self.config.getSwitch("ResourceDisk.Format", False):
            #TODO FreeBSD use Popen to open another process to do this
            #Need to investigate why?
            diskThread = threading.Thread(target = self.activateResourceDisk)
            diskThread.start()
            
        #TODO Start load balancer
        #Need to check whether this should be kept

        #Handle state change
        while True:
            agentStatus = "Ready"
            agentStatusDetail = "Guest Agent is running"
            #Handle extensions
            try:
                exthandler = ext.ExtensionHandler()
                exthandler.process()
            except Exception, e:
                logger.Error("Failed to handle extensions: {0}", e)
            self.protocol.reportAgentStatus(GuestAgentVersion, 
                                            agentStatus,
                                            agentStatusDetail)
            #Wait for 25 seconds and detect protocol again.
            time.sleep(25)
            self.protocol = protocol.DetectDefaultProtocol()

    def activateResourceDisk(self):
        mountpoint = self.config.get("ResourceDisk.MountPoint", "/mnt/resource")
        fs = self.config.get("ResourceDisk.Filesystem", "ext3")
        mountpoint = CurrOS.MountResourceDisk(mountpoint, fs)
        warningFile = os.path.join(mountpoint, DataLossWarningFile)
        fileutil.SetFileContents(warningFile, DataLossWarning)
        if self.config.getSwitch("ResourceDisk.EnabledSwap", False):
            sizeMB = self.config.getInt("ResourceDisk.SwapSizeMB", 0)
            CurrOS.CreateSwapSpace(mountpoint, sizeMB)

    def detectScvmmEnv(self):
        CurrOS.MountDvd()
        mountPoint = CurrOS.GetDvdMountPoint()
        return os.path.isfile(os.path.join(mountPoint, VmmConfigFileName))

    def startScvmmAgent(self):
        logger.Info("Starting Microsoft System Center VMM Initialization Process")
        mountPoint = CurrOS.GetDvdMountPoint()
        startupScript = os.path.join(mountPoint, VmmStartupScriptName)
        subprocess.Popen(["/bin/bash", startupScript, "-p " + mountPoint])

    def waitForNetwork(self):
        ipv4 = CurrOS.GetIpv4Address()
        while ipv4 == '' or ipv4 == '0.0.0.0':
            logger.Info("Waiting for network.")
            time.sleep(10)
            CurrOS.StartNetwork()
            ipv4 = CurrOS.GetIpv4Address()

    def savePid(self):
        fileutil.SetFileContents(CurrOS.GetAgentPidPath(), str(os.getpid()))

def ParseArgs():
    cmd = None
    force = False
    verbose = False
    for a in sys.argv[1:]:
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
        elif re.match("^([-/]*)(help|usage|\?)", a):
            cmd = "help"
        elif re.match("^([-/]*)verbose", a):
            verbose = True
        elif re.match("^([-/]*)force", a):
            force = True
    return cmd, force, verbose

def Version():
    print "{0} running on {1} {2}".format(GuestAgentVersion, 
                                          CurrOSInfo[0], 
                                          CurrOSInfo[1])
def Usage():
    print "usage: {0} [-verbose] [-force] "
          "[-help|-deprovision[+user]|-version|-serialconsole|-daemon]"

def Deprovision(force=False, deluser=False):
    configPath = CurrOS.GetConfigurationPath()
    config = conf.LoadConfiguration(configPath)
    print("WARNING! The waagent service will be stopped.")
    print("WARNING! All SSH host key pairs will be deleted.")
    print("WARNING! Cached DHCP leases will be deleted.")
    CurrOS.OnDeprovisionStart()

    delRootPasswd = config.getSwitch("Provisioning.DeleteRootPassword", False)
    if delRootPasswd:
        print("WARNING! root password will be disabled. "
              "You will not be able to login as root.")
    protocol = protocol.GetDefaultProtocol()
    ovf = protocol.getOvf()
    if ovf is not None and deluser:
        print("WARNING! {0} account and entire home directory will be deleted.",
              ovf.getUserName())
    
    if not force:
        confirm = raw_input("Do you wan to proceed (y/n)")
        if confirm.lower().startswith('y'):
            return

    CurrOS.StopAgentService()
    CurrOS.DeleteRootPassword()
    if config.getSwitch("Provisioning.RegenerateSshHostkey", False):
        shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
    CurrOS.SetHostname('localhost.localdomain')
    fileutil.ClearupDirs(CurrOS.GetLibDir(), "/var/lib/dhclient", 
                         "/var/lib/dhcpcd", "/var/lib/dhcp")
    fileutil.RemoveFiles('/root/.bash_history', '/var/log/waagent.log')
    CurrOS.OnDeprovision()
    if ovf is not None and deluser
        CurrOS.DeleteAccount(ovf.getUserName())

def Main():
    os.chdir(CurrOS.GetLibDir())
    logger.LoggerInit('/var/log/waagent.log', '/dev/console')
    command, force, verbose = ParseArgs()
    if command == "deprovision+user":
        Deprovision(force=force, deluser=True)
    elif command == "deprovision":
        Deprovision(force=force, deluser=False)
    elif command == "daemon":
        configPath = CurrOS.GetConfigurationPath()
        config = conf.LoadConfiguration(configPath)
        Agent(config).run()
    elif command == "version":
        Version()
    elif command == "serialconsole":
        #TODO
    else:#command == 'help' or anything not supported
        Usage()

