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
import re
import pwd
import shutil
import tempfile
import subprocess
import socket
import array
import struct
import fcntl
import time
import base64
import walinuxagent.logger as logger
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.utils.shellutil as shellutil
import walinuxagent.utils.textutil as textutil

RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
               "/etc/udev/rules.d/70-persistent-net.rules" ]

"""
Define distro specific behavior. DefaultDistro class defines default behavior 
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""
class DefaultDistro(object):
    def __init__(self):
        self.libDir = "/var/lib/waagent"
        self.dvdMountPoint = "/mnt/cdrom/secure"
        self.ovfenvPathOnDvd = "/mnt/cdrom/secure/ovf-env.xml"
        self.agentPidPath = "/var/run/waagent.pid"
        self.passwdPath = "/etc/shadow"
        self.home = '/home'
        self.sshdConfigPath = '/etc/ssh/sshd_config'
        self.opensslCmd = '/usr/bin/openssl'
        self.configPath = '/etc/waagent.conf'
        self.selinux=None

    def GetLibDir(self):
        return self.libDir

    def GetDvdMountPoint(self):
        return self.dvdMountPoint

    def GetConfigurationPath(self):
        return self.configPath

    def GetOvfEnvPathOnDvd(self):
        return self.ovfenvPathOnDvd

    def GetAgentPidPath(self):
        return self.agentPidPath

    def GetOpensslCmd(self):
        return self.opensslCmd

    def GetWireServerEndpoint(self):
        endpointFile = os.path.join(self.GetLibDir(), 'endpoint')
        if os.path.isfile(endpointFile):
            return fileutil.GetFileContents(endpointFile)
        return None

    def SetWireServerEndpoint(self, endpoint):
        if endpoint is None:
            return
        endpointFile = os.path.join(self.GetLibDir(), 'endpoint')
        fileutil.SetFileContents(endpointFile, endpoint)
        
    def UpdateUserAccount(self, userName, password, expiration=None):
        """
        Update password and ssh key for user account.
        New account will be created if not exists.
        """
        if userName is None:
            raise Exception("User name is empty")

        if self._IsSysUser(userName):
            raise Exception(("User {0} is a system user. "
                             "Will not set passwd.").format(userName))

        userentry = self.GetUserEntry(userName)
        if userentry is None:
            self._CreateUserAccount(userName, expiration)
            
        if password is not None:
            self.ChangePassword(userName, password)
        
        self.ConfigSudoer(userName, password is None)

    def GetUserEntry(self, userName):
        try:
            return pwd.getpwnam(userName)
        except KeyError:
            return None

    def _IsSysUser(self, userName):
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
   
    def _CreateUserAccount(self, userName, expiration=None):
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
        fileutil.SetFileContents('/etc/sudoers.d/waagent', sudoer, append=True)
        fileutil.ChangeMod('/etc/sudoers.d/waagent', 0440)

    def DeleteRootPassword(self):
        passwdContent = fileutil.GetFileContents(self.passwdPath)
        if passwdContent is None:
            raise Exception("Failed to delete root password.")
        passwd = passwdContent.split('\n')
        newPasswd = filter(lambda x : not x.startswith("root:"), passwd)
        newPasswd.insert(0, "root:*LOCK*:14600::::::")
        fileutil.ReplaceFileContentsAtomic(self.passwdPath, "\n".join(newPasswd))

    def GetHome(self):
        return self.home
    
    def GetPubKeyFromPrv(self, fileName):
        cmd = "{0} rsa -in {1} -pubout 2>/dev/null".format(self.opensslCmd,
                                                           fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def GetPubKeyFromCrt(self, fileName):
        cmd = "{0} x509 -in {1} -pubkey -noout".format(self.opensslCmd, 
                                                       fileName)
        pub = shellutil.RunGetOutput(cmd)[1]
        return pub

    def _NormPath(self, filepath):
        home = CurrOS.GetHome()
        # Expand HOME variable if present in path
        path = os.path.normpath(filepath.replace("$HOME", home))
        return path
        
    def GetThumbprintFromCrt(self, fileName):
        cmd="{0} x509 -in {1} -fingerprint -noout".format(self.opensslCmd, 
                                                            fileName)
        thumbprint = shellutil.RunGetOutput(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint
   
    def DeploySshKeyPair(self, userName, thumbprint, path):
        """
        Deploy id_rsa and id_rsa.pub
        """
        path = self._NormPath(path)
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
        path = self._NormPath(path)
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
        #TODO some distros doesn't support PKCS8. Need to figure out.
        shellutil.Run("ssh-keygen -i -m PKCS8 -f {0} >> {1}".format(thumbprint, 
                                                                    path))
        self.SetSelinuxContext(path, 'unconfined_u:object_r:ssh_home_t:s')
        os.chmod(path, 0600)
        os.chmod(pubPath, 0600)
            
    def IsSelinuxSystem(self):
        """
        Checks and sets self.selinux = True if SELinux is available on system.
        """
        if self.selinux == None:
            if shellutil.Run("which getenforce", chk_err=False) == 0:
                self.selinux = True
            else:
                self.selinux = False
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
        return self.sshdConfigPath

    def SetSshClientAliveInterval(self):
        configPath = self.GetSshdConfigPath()
        config = fileutil.GetFileContents(configPath).split("\n")
        textutil.SetSshConfig(config, "ClientAliveInterval", "180")
        fileutil.ReplaceFileContentsAtomic(configPath, '\n'.join(config))
        logger.Info("Configured SSH client probing to keep connections alive.")
   
    def ConfigSshd(self, disablePassword):
        option = "no" if disablePassword else "yes"
        configPath = self.GetSshdConfigPath()
        config = fileutil.GetFileContents(configPath).split("\n")
        textutil.SetSshConfig(config, "PasswordAuthentication", option)
        textutil.SetSshConfig(config, "ChallengeResponseAuthentication", option)
        fileutil.ReplaceFileContentsAtomic(configPath, "\n".join(config))
        logger.Info("Disabled SSH password-based authentication methods.")

    def RegenerateSshHostkey(self, keyPairType):
        shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
        shellutil.Run("ssh-keygen -N '' -t {0} -f /etc/ssh/ssh_host_{1}_key"
                .format(keyPairType, keyPairType))

    def GetSshHostKeyThumbprint(self, keyPairType):
        cmd = "ssh-keygen -lf /etc/ssh/ssh_host_{0}_key.pub".format(keyPairType)
        ret = shellutil.RunGetOutput(cmd)
        if ret[0] == 0:
            return ret[1].rstrip().split()[1].replace(':', '')
        else:
            return None

    def WaitForSshHostKey(self, keyPairType, maxRetry=6):
        path = '/etc/ssh/ssh_host_{0}_key'.format(keyPairType)
        for retry in range(0, maxRetry):
            if os.path.isfile(path):
                return
            logger.Info("Wait for ssh host key be generated: {0}", path)
            time.sleep(1)
        raise Exception("Can't find ssh host key.")

    def GetDvdDevice(self, devDir='/dev'):
        patten=r'(sr[0-9]|hd[c-z]|cdrom[0-9])'
        for dvd in [re.match(patten, dev) for dev in os.listdir(devDir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        return None

    def MountDvd(self, maxRetry=6, chk_err=True):
        dvd = self.GetDvdDevice()
        mountPoint = self.GetDvdMountPoint()
        #TODO Why do we need to load atapiix?
        #self.LoadAtapiixModule()
        mountlist = shellutil.RunGetOutput("mount")[1]
        existing = self._GetMountPoint(mountlist, dvd)
        if existing is not None: #Already mounted
            return
        if not os.path.isdir(mountPoint):
            os.makedirs(mountPoint)
        retcode = self.Mount(dvd, mountPoint, chk_err)
        for retry in range(0, maxRetry):
            if retcode == 0:
                logger.Info("Successfully mounted provision dvd")
                return
            else:
                logger.Warn("Mount dvd failed: retry={0}, ret={1}", 
                            retry, 
                            retcode)
            time.sleep(5)
            self.Mount(dvd, mountPoint, chk_err)
        if chk_err:
            raise Exception("Failed to mount provision dvd")

    def UmountDvd(self):
        mountPoint = self.GetDvdMountPoint()
        self.Umount(mountPoint)

    def LoadAtapiixModule(self):
        if self.IsAtaPiixModuleLoaded():
            return
        ret, kernVersion = shellutil.RunGetOutput("uname -r")
        if ret != 0:
            raise Exception("Failed to call uname -r")
        modulePath = os.path.join('/lib/modules', 
                                  kernVersion.strip('\n'),
                                  'kernel/drivers/ata/ata_piix.ko')
        if not os.path.isfile(modulePath):
            raise Exception("Can't find module file:{0}".format(modulePath))

        ret, output = shellutil.RunGetOutput("insmod " + modulePath)
        if ret != 0:
            raise Exception("Error calling insmod for ATAPI CD-ROM driver")
        if not self.IsAtaPiixModuleLoaded(maxRetry=3):
            raise Exception("Failed to load ATAPI CD-ROM driver") 

    def IsAtaPiixModuleLoaded(self, maxRetry=1):
        for retry in range(0, maxRetry):
            ret = shellutil.Run("lsmod | grep ata_piix", chk_err=False)
            if ret == 0:
                logger.Info("Module driver for ATAPI CD-ROM is already present.")
                return True
            time.sleep(1)
        return False
 
    def Mount(self, dvd, mountPoint, chk_err=True):
        return shellutil.RunGetOutput("mount {0} {1}".format(dvd, mountPoint), 
                                      chk_err)[0]

    def Umount(self, mountPoint):
        return "umount {0}".format(mountPoint)

    def OpenPortForDhcp(self):
        #Open DHCP port if iptables is enabled.
        # We supress error logging on error.
        shellutil.Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)      
        shellutil.Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)

    def GenerateTransportCert(self):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 32768 "
               "-newkey rsa:2048 -keyout TransportPrivate.pem "
               "-out TransportCert.pem").format(self.opensslCmd)
        shellutil.Run(cmd)

    def RemoveRulesFiles(self, rulesFiles=RulesFiles):
        libDir = self.GetLibDir()
        for src in rulesFiles:
            fileName = fileutil.GetLastPathElement(src)
            dest = os.path.join(libDir, fileName)
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(src):
                logger.Warn("Move rules file {0} to {1}", fileName, dest)
                shutil.move(src, dest)

    def RestoreRulesFiles(self, rulesFiles=RulesFiles):
        libDir = self.GetLibDir()
        for dest in rulesFiles:
            fileName = fileutil.GetLastPathElement(dest)
            src = os.path.join(libDir, fileName)
            if os.path.isfile(dest):
                continue
            if os.path.isfile(src):
                logger.Warn("Move rules file {0} to {1}", fileName, dest)
                shutil.move(src, dest)

    def CheckDependencies(self):
        #TODO Add dependency check
        pass

    def GetMacAddress(self):
        """
        Convienience function, returns mac addr bound to
        first non-loobback interface.
        """
        ifname=''
        while len(ifname) < 2 :
            ifname=self.GetFirstActiveNetworkInterfaceNonLoopback()[0]
        addr = self.GetInterfaceMac(ifname)        
        return textutil.HexStringToByteArray(addr)

    def GetInterfaceMac(self, ifname):
        """
        Return the mac-address bound to the socket.
        """
        sock = socket.socket(socket.AF_INET, 
                             socket.SOCK_DGRAM, 
                             socket.IPPROTO_UDP)
        param = struct.pack('256s', (ifname[:15]+('\0'*241)).encode('latin-1'))
        info = fcntl.ioctl(sock.fileno(), 0x8927, param)
        return ''.join(['%02X' % textutil.Ord(char) for char in info[18:24]])

    def GetFirstActiveNetworkInterfaceNonLoopback(self):
        """
        Return the interface name, and ip addr of the
        first active non-loopback interface.
        """
        iface=''
        expected=16 # how many devices should I expect...
        struct_size=40 # for 64bit the size is 40 bytes
        sock = socket.socket(socket.AF_INET, 
                             socket.SOCK_DGRAM, 
                             socket.IPPROTO_UDP)
        buff=array.array('B', b'\0' * (expected * struct_size))
        param = struct.pack('iL', 
                            expected*struct_size, 
                            buff.buffer_info()[0])
        ret = fcntl.ioctl(sock.fileno(), 0x8912, param)
        retsize=(struct.unpack('iL', ret)[0])
        if retsize == (expected * struct_size):
            logger.Warn(('SIOCGIFCONF returned more than {0} up '
                         'network interfaces.'), expected)
        sock = buff.tostring()
        for i in range(0, struct_size * expected, struct_size):
            iface=sock[i:i+16].split(b'\0', 1)[0]
            if iface == b'lo':
                continue
            else:
                break
        return iface.decode('latin-1'), socket.inet_ntoa(sock[i+20:i+24])

    def IsMissingDefaultRoute(self):
        routes = shellutil.RunGetOutput("route -n")[1]
        for route in routes:
            if route.startswith("0.0.0.0 ") or route.startswith("default "):
               return False 
        return True

    def GetInterfaceName(self):
        return self.GetFirstActiveNetworkInterfaceNonLoopback()[0]
    
    def GetIpv4Address(self):
        return self.GetFirstActiveNetworkInterfaceNonLoopback()[1]
    
    def SetBroadcastRouteForDhcp(self, ifname):
        return shellutil.Run("route add 255.255.255.255 dev {0}".format(ifname),
                             chk_err=False)

    def RemoveBroadcastRouteForDhcp(self, ifname):
        shellutil.Run("route del 255.255.255.255 dev {0}".format(ifname), 
                      chk_err=False)

    def IsDhcpEnabled(self):
        return False

    def StopDhcpService(self):
        raise NotImplementedError('StopDhcpService method missing')

    def StartDhcpService(self):
        raise NotImplementedError('StartDhcpService method missing')

    def StartNetwork(self):
        raise NotImplementedError('StartNetwork method missing')

    def StartAgentService(self):
        raise NotImplementedError('StartAgentService method missing')

    def StopAgentService(self):
        raise NotImplementedError('StopAgentService method missing')

    def RegisterAgentService(self):
        self.StartAgentService()

    def UnregisterAgentService(self):
        self.StopAgentService()

    def RestartSshService(self):
        raise NotImplementedError('RestartSshService method missing')
    
    def RouteAdd(self, net, mask, gateway):
        """
        Add specified route using /sbin/route add -net.
        """
        cmd = ("/sbin/route add -net "
               "{0} netmask {1} gw {2}").format(net, mask, gateway)
        return shellutil.Run(cmd, chk_err=False)

    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

    def SetHostname(self, hostname):
        fileutil.SetFileContents('/etc/hostname', hostname)
        shellutil.Run("hostname {0}".format(hostname), chk_err=False)

    def SetDhcpHostname(self, hostname):
        raise NotImplementedError('SetDhcpHostname method missing')

    def RestartInterface(self, ifname):
        shellutil.Run("ifdown {0} && ifup {1}".format(ifname, ifname))

    def PublishHostname(self, hostname):
        self.SetDhcpHostname(hostname)
        ifname = self.GetInterfaceName()
        self.RestartInterface(ifname)

    def SetScsiDiskTimeout(self, timeout):
        for dev in os.listdir("/sys/block"):
            if dev.startswith('sd'):
                self.SetBlockDeviceTimeout(dev, timeout)

    def SetBlockDeviceTimeout(self, dev, timeout):
        if dev is not None and timeout is not None:
            filePath = "/sys/block/{0}/device/timeout".format(dev)
            original = fileutil.GetFileContents(filePath).splitlines()[0].rstrip()
            if original != timeout:
                fileutil.SetFileContents(filePath, timeout)
                logger.Info("Set block dev timeout: {0} with timeout: {1}",
                            dev,
                            timeout)
    def _GetMountPoint(self, mountlist, device):
        """
        Example of mountlist:
            /dev/sda1 on / type ext4 (rw)
            proc on /proc type proc (rw)
            sysfs on /sys type sysfs (rw)
            devpts on /dev/pts type devpts (rw,gid=5,mode=620)
            tmpfs on /dev/shm type tmpfs 
            (rw,rootcontext="system_u:object_r:tmpfs_t:s0")
            none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)
            /dev/sdb1 on /mnt/resource type ext4 (rw)
        """
        if (mountlist and device):
            for entry in mountlist.split('\n'):
                if(re.search(device, entry)):
                    tokens = entry.split()
                    #Return the 3rd column of this line
                    return tokens[2] if len(tokens) > 2 else None
        return None

    def MountResourceDisk(self, mountpoint, fs):
        device = self.DeviceForIdePort(1)
        if device is None:
            logger.Error("Activate resource disk failed: "
                         "unable to detect disk topology")
            return None
        device = "/dev/" + device
        mountlist = shellutil.RunGetOutput("mount")[1]
        existing = self._GetMountPoint(mountlist, device)
        if(existing):
            logger.Info("Resource disk {0} is already mounted", device)
            return existing

        fileutil.CreateDir(mountpoint, "root", 0755)  
        output = shellutil.RunGetOutput("sfdisk -q -c {0} 1".format(device))
        if output[1].rstrip() == "7" and fs != "ntfs":
            shellutil.Run("sfdisk -c {0} 1 83".format(device))
            shellutil.Run("mkfs.{0} {1}1".format(fs, device))
        ret = shellutil.Run("mount {0}1 {1}".format(device, mountpoint))
        if ret:
            logger.Error("Failed to mount resource disk ({0})".format(device))
            raise Exception("Failed to mount resource disk")
        else:
            logger.Info(("Resource disk ({0}) is mounted at {1} "
                         "with fstype {2}").format(device, mountpoint, fs))
            return mountpoint

    def DeviceForIdePort(self, n):
        """
        Return device name attached to ide port 'n'.
        """
        if n > 3:
            return None
        g0 = "00000000"
        if n > 1:
            g0 = "00000001"
            n = n - 2
        device = None
        path = "/sys/bus/vmbus/devices/"
        for vmbus in os.listdir(path):
            deviceid = fileutil.GetFileContents(os.path.join(path, 
                                                             vmbus, 
                                                             "device_id"))
            guid = deviceid.lstrip('{').split('-')
            if guid[0] == g0 and guid[1] == "000" + str(n):
                for root, dirs, files in os.walk(path + vmbus):
                    if root.endswith("/block"):
                        device = dirs[0]
                        break
                    else : #older distros
                        for d in dirs:
                            if ':' in d and "block" == d.split(':')[0]:
                                device = d.split(':')[1]
                                break
                break
        return device


    def CreateSwapSpace(self, mountpoint, sizeMB):
        sizeKB = sizeMB * 1024
        size = sizeKB * 1024
        swapfile = os.path.join(mountpoint, 'swapfile')
        if os.path.isfile(swapfile) and os.path.getsize(swapfile) != size:
            os.remove(swapfile)
        if not os.path.isfile(swapfile):
            shellutil.Run(("dd if=/dev/zero of={0} bs=1024 "
                           "count={1}").format(swapfile, sizeKB))
            shellutil.Run("mkswap {0}".format(swapfile))
        if shellutil.Run("swapon {0}".format(swapfile)):
            logger.Error("Failed to activate swap at: {0}".format(swapfile))
        else:
            logger.Info("Enabled {0}KB of swap at {1}".format(sizeKB, swapfile))

    def DeleteAccount(self, userName):
        if self._IsSysUser(userName):
            logger.Error("{0} is a system user. Will not delete it.", userName)
        shellutil.Run("> /var/run/utmp")
        shellutil.Run("userdel -f -r " + userName)
        #Remove user from suders
        sudoers = fileutil.GetFileContents("/etc/sudoers.d/waagent").split()
        sudoers = filter(lambda x : userName not in x, sudoers)
        fileutil.SetFileContents("/etc/sudoers.d/waagent", "\n".join(sudoers))

    def OnDeprovisionStart(self):
        print ("WARNING! Nameserver configuration in "
               "/etc/resolv.conf will be deleted.")

    def OnDeprovision(self):
        """
        Distro specific clean up work during deprovision
        """
        fileutil.RemoveFiles('/etc/resolv.conf')

    def TranslateCustomData(self, data):
        return data

class DebianDistro(DefaultDistro):
    def __init__(self):
        super(DebianDistro, self).__init__()
        self.dhcpClientConfigFile = '/etc/dhcp/dhclient.conf'

    def RestartSshService(self):
        return shellutil.Run("service sshd restart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("service walinuxagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("service walinuxagent start", chk_err=False)

    def SetDhcpHostname(self, hostname):
        config = fileutil.GetFileContents(self.dhcpClientConfigFile).split("\n")
        config = filter(lambda x : x.startswith("send host-name"))
        config.append("send host-name", hostname)
        fileutil.ReplaceFileContentsAtomic(self.dhcpClientConfigFile,
                                           "\n".join(config))

class UbuntuDistro(DebianDistro):
    def __init__(self):
        super(UbuntuDistro, self).__init__()

    def StartNetwork(self):
        return shellutil.Run("service networking start", chk_err=False)

    def SetDhcpHostname(self, hostname):
        pass

    def OnDeprovisionStart(self):
        print("WARNING! Nameserver configuration in "
              "/etc/resolvconf/resolv.conf.d/{tail,originial} will be deleted.")

    def OnDeprovision(self):
        if os.path.realpath('/etc/resolv.conf') != '/run/resolvconf/resolv.conf':
            logger.Info("resolvconf is not configured. Removing /etc/resolv.conf")
            fileutil.RemoveFiles('/etc/resolv.conf')
        else:
            logger.Info("resolvconf is enabled; leaving /etc/resolv.conf intact")
            fileutil.RemoveFiles('/etc/resolvconf/resolv.conf.d/tail',
                                 '/etc/resolvconf/resolv.conf.d/originial')

class Ubuntu1204Distro(UbuntuDistro):
    def __init__(self):
        super(Ubuntu1204Distro, self).__init__()

    #Override
    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof dhclient3")
        return ret[1] if ret[0] == 0 else None

class RedhatDistro(DefaultDistro):
    def __init__(self):
        super(RedhatDistro, self).__init__()
        self.sshdConfigPath = '/etc/ssh/sshd_config'
        self.opensslCmd = '/usr/bin/openssl'
        self.configPath = '/etc/waagent.conf'
        self.selinux=None

    def StartNetwork(self):
        return shellutil.Run("/sbin/service networking start", chk_err=False)

    def RestartSshService(self):
        return shellutil.Run("/sbin/service sshd condrestart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("/sbin/service waagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("/sbin/service waagent start", chk_err=False)

    #Override
    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

class Redhat7Distro(RedhatDistro):
    def __init__(self):
        super(Redhat7Distro, self).__init__()

    def SetHostname(self, hostname):
        fileutil.UpdateConfigFile('/etc/sysconfig/network', 
                                  'HOSTNAME',
                                  'HOSTNAME={0}'.format(hostname))
    
    def SetDhcpHostname(self, hostname):
        ifname = self.GetInterfaceName()
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        fileutil.UpdateConfigFile(filepath,
                                  'DHCP_HOSTNAME',
                                  'DHCP_HOSTNAME={0}'.format(hostname))

class FedoraDistro(DefaultDistro):
    pass

class CoreOSDistro(DefaultDistro):
    def __init(self):
        super(CoreOSDistro, self).__init__()
        self.configPath = '/usr/share/oem/waagent.conf'

    def _IsSysUser(self, userName):
       #User 'core' is not a sysuser
       if userName == 'core':
           return False
       return super(CoreOSDistro, self).isSysUser(userName)

    def IsDhcpEnabled(self):
        return True
    
    def StartNetwork(self) :
        return shellutil.Run("systemctl start systemd-networkd", chk_err=False)
        
    def RestartInterface(self, iface):
        Run("systemctl restart systemd-networkd")

    def RestartSshService(self):
        return shellutil.Run("systemctl restart sshd", chk_err=False)

    def StopDhcpService(self):
        return shellutil.Run("systemctl stop systemd-networkd", chk_err=False)

    def StartDhcpService(self):
        return shellutil.Run("systemctl start systemd-networkd", chk_err=False)

    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof systemd-networkd")
        return ret[1] if ret[0] == 0 else None
    
    def OnDeprovisionStart(self):
        print "WARNING! /etc/machine-id will be removed."

    def OnDeprovision(self):
        fileutil.RemoveFiles('/etc/machine-id')

    def TranslateCustomData(self, data):
        return base64.b64decode(data)

class GentooDistro(DefaultDistro):
    pass

class SUSEDistro(DefaultDistro):
    def __init__(self):
        super(SUSEDistro, self).__init__()
        self.dhcpClientName='dhcpcd'

    def SetHostname(self, hostname):
        fileutil.SetFileContents('/etc/HOSTNAME', hostname)
        shellutil.Run("hostname {0}".format(hostname), chk_err=False)

    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof {0}".format(self.dhcpClientName))
        return ret[1] if ret[0] == 0 else None
    
    def IsDhcpEnabled(self):
        return True

    def StopDhcpService(self):
        cmd = "/sbin/service {0} stop".format(self.dhcpClientName)
        return shellutil.Run(cmd, chk_err=False)

    def StartDhcpService(self):
        cmd = "/sbin/service {0} start".format(self.dhcpClientName)
        return shellutil.Run(cmd, chk_err=False)

    def StartNetwork(self) :
        return shellutil.Run("/sbin/service start networking", chk_err=False)

    def RestartSshService(self):
        return shellutil.Run("/sbin/service sshd restart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("/sbin/service waagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("/sbin/service waagent start", chk_err=False)
    
    def RegisterAgentService(self):
        ret = shellutil.Run("insserv waagent", chk_err=False)
        if ret != 0:
            return ret
        ret = super(SUSEDistro, self).RegisterAgentService()
        return ret
    
    def UnregisterAgentService(self):
        ret = super(SUSEDistro, self).UnregisterAgentService()
        if ret != 0:
            return ret
        return shellutil.Run("insserv -r waagent", chk_err=False)

class SUSE12Distro(SUSEDistro):
    def __init__(self):
        super(SUSE12Distro, self).__init__()
        self.dhcpClientName = 'wickedd-dhcp4'

class FreeBSDDistro(DefaultDistro):
    def __init__(self):
        self.scsiConfigured = False

    def SetScsiDiskTimeout(self, timeout):
        if scsiConfigured:
            return
        shellutil.Run("sysctl kern.cam.da.default_timeout=" + timeout)
        self.scsiConfigured = True

def GetDistroInfo():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', str(platform.release()))
        distroInfo = ['freebsd', release, '', 'freebsd']
    if 'linux_distribution' in dir(platform):
        distroInfo = list(platform.linux_distribution(full_distribution_name = 0))
        fullName = platform.linux_distribution()[0]
        distroInfo.append(fullName)
    else:
        distroInfo = platform.dist()

    #Remove trailing whitespace and quote in distro name
    distroInfo[0] = distroInfo[0].strip('"').strip(' ').lower() 
    return distroInfo

def GetDistro(distroInfo):
    name = distroInfo[0]
    version = distroInfo[1]
    codeName = distroInfo[2]
    fullName = distroInfo[3]

    if name == 'ubuntu':
        if version == '12.04':
            return Ubuntu1204Distro()
        else:
            return UbuntuDistro()
    elif name == 'centos' or name == 'redhat':
        if version < '7.0':
            return RedhatDistro()
        else:
            return Redhat7Distro()
    elif name == 'fedora':
        return FedoraDistro()
    elif name == 'debian':
        return DebianDistro()
    elif name == 'coreos':
        return CoreOSDistro()
    elif name == 'gentoo':
        return CoreOSDistro()
    elif name == 'suse':
        if fullName == 'SUSE Linux Enterprise Server' and version < '12' \
                or fullName == 'openSUSE' and version < '13.2':
            return SUSEDistro()
        else:
            return SUSE12Distro()
    elif name == 'freebsd':
        return FreeBSDDistro()
    return DefaultDistro()

CurrOSInfo = GetDistroInfo()
CurrOS = GetDistro(CurrOSInfo)
