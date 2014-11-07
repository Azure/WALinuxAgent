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

RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
               "/etc/udev/rules.d/70-persistent-net.rules" ]

"""
Define distro specific behavior. DefaultDistro class defines default behavior 
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""
class DefaultDistro():
    def GetLibDir(self):
        return "/var/lib/waagent"

    def GetDvdMountPoint(self):
        return "/mnt/cdrom/secure"

    def GetOvfEnvPathOnDvd(self):
        return "/mnt/cdrom/secure/ovf-env.xml"

    def GetAgentPidPath(self):
        return '/var/run/waagent.pid'

    def UpdateUserAccount(self, userName, password, expiration=None):
        """
        Update password and ssh key for user account.
        New account will be created if not exists.
        """
        if userName is None:
            raise Exception("User name is empty")

        if self.IsSysUser(userName):
            raise Exception(("User {0} is a system user. "
                             "Will not set passwd.").format(userName))

        userentry = self.GetUserEntry(userName)
        if userentry is None:
            self.CreateUserAccount(userName, expiration)
            
        if password is not None:
            self.ChangePassword(userName, password)
        
        self.ConfigSudoer(userName, password is None)

    def GetUserEntry(self, userName):
        try:
            return pwd.getpwnam(userName)
        except KeyError:
            return None

    def IsSysUser(self, userName):
        userentry = self.GetUserEntry(userName)
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
   
    def CreateUserAccount(self, userName, expiration):
        cmd = "useradd -m {0}".format(userName)
        if expiration is not None:
            cmd = "{0} -e {1}".format(cmd, expiration)
        retcode, out = shellutil.RunGetOutput(cmd)
        if retcode != 0:
            raise Exception(("Failed to create user account:{0}, "
                             "retcode:{1}, "
                             "output:{2}").format(userName, retcode, out))

    def ChangePassword(self, userName, password):
        shellutil.RunSendStdin("chpasswd", 
                               "{0}:{1}\n".format(userName, password))
            
    def ConfigSudoer(self, userName, nopasswd):
        # for older distros create sudoers.d
        if not os.path.isdir('/etc/sudoers.d/'):
            # create the /etc/sudoers.d/ directory
            os.mkdir('/etc/sudoers.d/')
            # add the include of sudoers.d to the /etc/sudoers
            sudoers = fileutil.GetFileContents('/etc/sudoers')
            sudoers = sudoers + '\n' + '#includedir /etc/sudoers.d/\n'
            fileutil.SetFileContents('/etc/sudoers', sudoers)
        sudoer = None
        if nopasswd:
            sudoer = "{0} ALL = (ALL) NOPASSWD\n".format(userName)
        else:
            sudoer = "{0} ALL = (ALL) ALL\n".format(userName)
        fileutil.SetFileContents('/etc/sudoers.d/waagent', sudoer)
        os.chmod('/etc/sudoers.d/waagent', 0440)
  
    def DeleteRootPassword(self):
        pass

    def GetHome(self):
        return '/home'
    
    def GetPubKeyFromPrv(self, fileName):
        cmd = "{0} rsa -in {1} -pubout 2>/dev/null".format(self.GetOpensslCmd(),
                                                           fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def GetPubKeyFromCrt(self, fileName):
        cmd = "{0} x509 -in {1} -pubkey -noout".format(self.GetOpensslCmd(), 
                                                       fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def NormPath(self, filepath):
        home = CurrOS.GetHome()
        # Expand HOME variable if present in path
        path = os.path.normpath(filepath.replace("$HOME", home))
        
    def GetThumbprintFromCrt(self, fileName):
        cmd="{0} x509 -in {1} -fingerprint -noout".format(self.GetOpensslCmd(), 
                                                            fileName)
        thumbprint = shellutil.RunGetOutput(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint
   
    def DeploySshKeyPair(self, userName, thumbprint, path):
        """
        Deploy id_rsa and id_rsa.pub
        """
        path = self.NormPath(path)
        dirPath = os.path.dirname(path)
        fileutil.CreateDir(dirPath, userName, 0700)
        libDir = CurrOS.GetLibDir()
        prvPath = os.path.join(libDir, thumbprint + '.prv')
        if not os.path.isfile(prvPath):
            logger.Error("Failed to deploy key pair, thumbprint: {0}", 
                         thumbprint)
            return
        shutil.copyfile(prvPath, path)
        pubPath = path + '.pub'
        pub = self.GetPubKeyFromPrv(prvPath)
        fileutil.SetFileContents(pubPath, pub)
        self.SetSelinuxContext(path, 'unconfined_u:object_r:ssh_home_t:s')
        self.SetSelinuxContext(pubPath, 'unconfined_u:object_r:ssh_home_t:s')
        os.chmod(path, 0600)
        os.chmod(pubPath, 0600)

    def DeploySshPublicKey(self, userName, thumbprint, path):
        """
        Deploy authorized_key
        """
        path = self.NormPath(path)
        dirPath = os.path.dirname(path)
        fileutil.CreateDir(dirPath, userName, 0700)
        libDir = CurrOS.GetLibDir()
        crtPath = os.path.join(libDir, thumbprint + '.crt')
        if not os.path.isfile(crtPath):
            logger.Error("Failed to deploy public key, thumbprint: {0}", 
                         thumbprint)
            return
        pubPath = os.path.join(libDir, thumbprint + '.pub')
        pub = self.GetPubKeyFromCrt(crtPath)
        fileutil.SetFileContents(pubPath, pub)
        self.SetSelinuxContext(pubPath, 'unconfined_u:object_r:ssh_home_t:s')
        shellutil.Run("ssh-keygen -i -m PKCS8 -f {0} >> {1}", thumbprint, path)
        self.SetSelinuxContext(path, 'unconfined_u:object_r:ssh_home_t:s')
        os.chmod(path, 0600)
        os.chmod(pubPath, 0600)
            
    def IsSelinuxSystem(self):
        """
        Checks and sets self.selinux = True if SELinux is available on system.
        """
        if self.selinux == None:
            if shellutil.Run("which getenforce", chk_err=False):
                self.selinux = False
            else:
                self.selinux = True
        return self.selinux
    
    def IsSelinuxRunning(self):
        """
        Calls shell command 'getenforce' and returns True if 'Enforcing'.
        """
        if self.IsSelinuxSystem():
            output = shellutil.RunGetOutput("getenforce")[1]
            return output.startswith("Enforcing")
        else:
            return False
        
    def SetSelinuxEnforce(self, state):
        """
        Calls shell command 'setenforce' with 'state' 
        and returns resulting exit code.
        """
        if self.IsSelinuxSystem():
            if state: s = '1'
            else: s='0'
            return shellutil.Run("setenforce "+s)

    def SetSelinuxContext(self, path, cn):
        """
        Calls shell 'chcon' with 'path' and 'cn' context.
        Returns exit result.
        """
        if self.IsSelinuxSystem():
            return shellutil.Run('chcon ' + cn + ' ' + path)
    
    def GetSshdConfigPath(self):
        return "/etc/ssh/sshd_config"
    
    def ConfigSshd(self, disablePassword):
        if not disablePassword:
            return
        configPath = self.GetSshdConfigPath()
        config = fileutil.GetFileContents(configPath).split("\n")
        passwordAuthFound = False
        challengeAuthFound = False
        for i in range(0, len(config)):
            if config[i].startswith("PasswordAuthentication"):
                passwordAuthFound = True
                config[i] = "PasswordAuthentication no"
            elif config[i].startswith("ChallengeResponseAuthentication"):
                challengeAuthFound = True
                config[i] = "ChallengeResponseAuthentication no"
            elif config[i].startswith("Match"):
                #Match block must be put in the end of sshd config
                break

        if not passwordAuthFound:
            config.insert(i, "PasswordAuthentication no")
        if not challengeAuthFound:
            config.insert(i, "ChallengeResponseAuthentication no")

        logger.Info("Disabled SSH password-based authentication methods.")
        fileutil.ReplaceFileContentsAtomic(configPath, "\n".join(config))

    def RegenerateSshHostkey(self, keyPairType):
        shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
        shellutil.Run("ssh-keygen -N '' -t {0} -f /etc/ssh/ssh_host_{1}_key"
                .format(keyPairType, keyPairType))

    def GetOpensslCmd(self):
        return '/usr/bin/openssl'

    def GetDvdDevice(self, devDir='/dev'):
        patten=r'(sr[0-9]|hd[c-z]|cdrom[0-9]|cd[0-9]?)'
        for dvd in [re.match(patten, dev) for dev in os.listdir(devDir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        return None

    def MountDvd(self, maxRetry=6):
        dvd = CurrentDistro.getDvdDevice()
        mountPoint = CurrentDistro.getDvdMountPoint()
        #Why do we need to load atapiix?
        #TODO load atapiix
        if not os.path.exits(mountPoint):
            os.makedirs(mountPoint)
        CurrentDistro.mountDvd(dvd, mountPoint)
        for retry in range(0, maxRetry):
            if retcode == 0:
                logger.Info("Successfully mounted provision dvd")
                return
            else:
                logger.Warn("Mount dvd failed: retry={0}, ret={1}", 
                            retry, 
                            retcode)
            time.sleep(5)
            CurrentDistro.mount(dvd, mountPoint)
        raise Exception("Failed to mount provision dvd")

    def UmountDvd(self):
        mountPoint = CurrentDistro.getDvdMountPoint()
        self.umount(mountPoint)
 
    def Mount(self, dvd, mountPoint):
        return RunGetOutput("mount {0} {1}".format(dvd, mountPoint))

    def Umount(self, mountPoint):
        return "umount {0}".format(mountPoint)

    def OpenPortForDhcp():
        #Open DHCP port if iptables is enabled.
        # We supress error logging on error.
        Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)      
        Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)

    def GenerateTransportCert():
        """
        Create ssl certificate for https communication with endpoint server.
        """
        opensslCmd = GetOpensslCmd()
        cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 32768 "
               "-newkey rsa:2048 -keyout TransportPrivate.pem "
               "-out TransportCert.pem").format(opensslCmd)
        shellutil.Run(cmd)

    def RemoveRulesFiles(self, rulesFiles=RulesFiles):
        libDir = self.GetLibDir()
        for src in rulesFiles:
            fileName = GetLastPathElement(src)
            dest = os.path.join(libDir, fileName)
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(src):
                logger.Warn("Move rules file {0} to {1}", fileName, dest)
                shutil.move(src, dest)

    def RestoreRulesFiles(self, rulesFiles=RulesFiles):
        libDir = self.GetLibDir()
        for dest in rulesFiles:
            fileName = GetLastPathElement(dest)
            src = os.path.join(libDir, fileName)
            if os.path.isfile(dest):
                continue
            if os.path.isfile(src):
                logger.Warn("Move rules file {0} to {1}", fileName, dest)
                shutil.move(src, dest)

    def CheckDependencies(self):
        pass

    def GetMacAddress(self):
        pass

    def SetBroadcastRouteForDhcp(self):
        pass

    def RemoveBroadcastRouteForDhcp(self):
        pass

    def IsDhcpEnabled(self):
        return False

    def StopDhcpService(self):
        pass

    def StartDhcpService(self):
        pass

    def StartNetwork(self):
        pass

    def RegisterAgentService(self):
        pass

    def UnregisterAgentService(self):
        pass

    def SetSshClientAliveInterval(self):
        filepath = "/etc/ssh/sshd_config"
        options = filter(lambda opt: not opt.startswith("ClientAliveInterval"), 
                        GetFileContents(filepath).split('\n'))
        options.append("ClientAliveInterval 180")
        fileutil.ReplaceFileContentsAtomic(filepath, '\n'.join(options))
        logger.Info("Configured SSH client probing to keep connections alive.")
   
    def GetRestartSshServiceCmd(self):
        return "service sshd restart"

    def RestartSshService(self):
        cmd = self.GetRestartSshServiceCmd()
        retcode = shellutil.Run(cmd)
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
    def IsSysUser(self, userName):
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

CurrOSInfo = GetDistroInfo()
CurrOS = GetDistro(CurrOSInfo)
