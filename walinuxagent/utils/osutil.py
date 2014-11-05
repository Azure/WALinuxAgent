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

import platform
import os
import pwd
import shutil
import tempfile
import subprocess
import walinuxagent.logger as logger
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.utils.shellutil as shellutil

LibDir = '/var/lib/waagent'
OvfMountPoint='/mnt/cdrom/secure'
OvfEnvPathOnDvd = '/mnt/cdrom/secure/ovf-env.xml'

def GetLibDir():
    return CurrentDistro.getLibDir()

def GetOvfMountPoint():
    return CurrentDistro.GetOvfMountPoint()

def GetOvfEnvPathOnDvd():
    return CurrentDistro.getOvfEnvPathOnDvd()

def OpenPortForDhcp():
    #Open DHCP port if iptables is enabled.
    # We supress error logging on error.
    Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)      
    Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)

def CreateUserAccount(userName, password, expiration):
    return CurrentDistro.createUserAccount(userName, password, expiration)

def GetOpensslCmd():
    return CurrentDistro.getOpensslCmd()

RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
               "/etc/udev/rules.d/70-persistent-net.rules" ]
def RemoveRulesFiles(rulesFiles=RulesFiles, libDir = LibDir):
    for src in rulesFiles:
        fileName = GetLastPathElement(src)
        dest = os.path.join(libDir, fileName)
        if os.path.isfile(dest):
            os.remove(dest)
        if os.path.isfile(src):
            logger.Warn("Move rules file {0} to {1}", fileName, dest)
            shutil.move(src, dest)

def RestoreRulesFiles(rulesFiles=RulesFiles, libDir = LibDir):
    for dest in rulesFiles:
        fileName = GetLastPathElement(dest)
        src = os.path.join(libDir, fileName)
        if os.path.isfile(dest):
            continue
        if os.path.isfile(src):
            logger.Warn("Move rules file {0} to {1}", fileName, dest)
            shutil.move(src, dest)

def GetMacAddress():
    pass

def SetBroadcastRouteForDhcp():
    pass

def IsDhcpEnabled():
    return CurrentDistro.isDhcpEnabled()

def StartDhcpService():
    return CurrentDistro.startDhcpService()

def StopDhcpService():
    return CurrentDistro.stopDhcpService()

def GenerateTransportCert():
    """
    Create ssl certificate for https communication with endpoint server.
    """
    opensslCmd = GetOpensslCmd()
    cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 32768 "
           "-newkey rsa:2048 -keyout TransportPrivate.pem "
           "-out TransportCert.pem").format(opensslCmd)
    shellutil.Run(cmd)
  
"""
Define distro specific behavior. DefaultDistro class defines default behavior 
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""
class DefaultDistro():
    def getLibDir(self):
        return "/var/lib/waagent"

    def getOvfMountPoint(self):
        return "/mnt/cdrom/secure"

    def getOvfEnvPathOnDvd(self):
        return "/mnt/cdrom/secure/ovf-env.xml"

    def isSysUser(self, userName):
        uidmin = None
        try:
            uidminDef = GetLineStartingWith("UID_MIN", "/etc/login.defs")
            uidmin = int(uidminDef.split()[1])
        except:
            pass
        if uidmin == None:
            uidmin = 100
        if userentry != None and userentry[2] < uidmin:
            return True
        else:
            return False

    def createUserAccount(self, userName, password, expiration):
        userentry = pwd.getpwnam(user)
        if userentry is None:
            cmd = "useradd -m {0}".format(user)
            if expiration is not None:
                cmd = "{0} -e {1}".format(cmd, expiration)
            retcode, out = shellutil.RunGetOutput(cmd)
            if retcode != 0:
                raise Exception(("Failed to create user account:{0}, "
                                 "retcode:{1}, "
                                 "output:{2}").format(userName, retcode, out))
        if password is not None:
            shellutil.RunSendStdin("chpasswd", 
                                   "{0}:{1}\n".format(userName, password))


    def regenerateSshHostkey(self, keyPairType):
        shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
        shellutil.Run("ssh-keygen -N '' -t {0} -f /etc/ssh/ssh_host_{1}_key"
                .format(keyPairType, keyPairType))
        self.restartSshService()

    def getOpensslCmd(self):
        return '/usr/bin/openssl'

    def getDvdDevice(self, devDir='/dev'):
        patten=r'(sr[0-9]|hd[c-z]|cdrom[0-9]|cd[0-9]?)'
        for dvd in [re.match(patten, dev) for dev in os.listdir(devDir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        return None

    def getMountCmd(self):
        return "mount"

    def mountDvd(self, dvd, mountPoint, maxRetry=6):
        if not os.path.exits(mountPoint):
            os.makedirs(mountPoint)

        cmd = "{0} {1} {2}".format(self.getMountCmd(), dvd, mountPoint)
        retcode, output = RunGetOutput(cmd)
        for retry in range(0, maxRetry):
            if retcode == 0:
                logger.Info("Successfully mounted provision dvd")
                return
            else:
                logger.Warn("Mount dvd failed: retry={0}, ret={1}", 
                            retry, 
                            retcode)
            time.sleep(5)
            retcode, output = RunGetOutput(cmd)
        raise Exception("Failed to mount provision dvd")

    def checkDependencies(self):
        pass

    def setBroadcastRouteForDhcp(self):
        pass

    def removeBroadcastRouteForDhcp(self):
        pass

    def isDhcpEnabled(self):
        return False

    def stopDhcpService(self):
        pass

    def startDhcpService(self):
        pass

    def restartNetwork(self):
        pass

    def registerAgentService(self):
        pass

    def unregisterAgentService(self):
        pass

    def setSshClientAliveInterval(self):
        filepath = "/etc/ssh/sshd_config"
        options = filter(lambda opt: not opt.startswith("ClientAliveInterval"), 
                        GetFileContents(filepath).split('\n'))
        options.append("ClientAliveInterval 180")
        fileutil.ReplaceFileContentsAtomic(filepath, '\n'.join(options))
        logger.Info("Configured SSH client probing to keep connections alive.")
   
    def getRestartSshServiceCmd(self):
        return "service sshd restart"

    def restartSshService(self):
        cmd = self.getRestartSshServiceCmd()
        retcode = Run(cmd)
        if retcode > 0:
            logger.Error("Failed to restart SSH service with return code:{0}",
                         retcode)
        return retcode

    
class DebianDistro(DefaultDistro):
    pass

class UbuntuDistro(DefaultDistro):
    pass

class RedHatDistro(DefaultDistro):
    pass

class FedoraDistro(DefaultDistro):
    pass

class CoreOSDistro(DefaultDistro):
    def isSysUser(self, userName):
       return super(CoreOSDistro, self).isSysUser(userName)

class GentooDistro(DefaultDistro):
    pass

class SUSEDistro(DefaultDistro):
    pass

def GetDistroInfo():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', str(platform.release()))
        distroInfo = ['freebsd', release, '']
    if 'linux_distribution' in dir(platform):
        distroInfo = list(platform.linux_distribution(full_distribution_name = 0))
    else:
        distroInfo = platform.dist()

    #Remove trailing whitespace and quote in distro name
    distroInfo[0] = distroInfo[0].strip('"').strip(' ').lower() 
    return distroInfo

def GetDistro(distroInfo):
    name = distroInfo[0]
    version = distroInfo[1]
    codeName = distroInfo[2]

    if name == 'ubuntu':
        return UbuntuDistro()
    elif name == 'centos' or name == 'redhat':
        return RedhatDistro()
    elif name == 'fedora':
        return FedoraDistro()
    elif name == 'debian':
        return DebianDistro()
    elif name == 'coreos':
        return CoreOSDistro()
    elif name == 'gentoo':
        return CoreOSDistro()
    elif name == 'suse':
        return SUSEDistro()
    else:
        return DefaultDistro()

CurrentDistroInfo = GetDistroInfo()
CurrentDistro = GetDistro(CurrentDistroInfo)

