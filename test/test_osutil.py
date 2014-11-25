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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import env
from test.tools import *
import uuid
import unittest
import os
import shutil
import time
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.utils.shellutil as shellutil
import walinuxagent.utils.osutil as osutil
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.conf as conf
import test

class TestGetDistro(unittest.TestCase):
    def test_get_distro(self):
        distroInfo = osutil.GetDistroInfo()
        self.assertNotEquals(None, distroInfo)
        self.assertNotEquals(None, distroInfo[0])
        self.assertNotEquals(None, distroInfo[1])
        self.assertNotEquals(None, distroInfo[2])
        self.assertNotEquals(None, distroInfo[3])
        distro = osutil.GetDistro(distroInfo)
        self.assertNotEquals(None, distro)

    def test_current_distro(self):
        self.assertNotEquals(None, osutil.CurrOSInfo)
        self.assertNotEquals(None, osutil.CurrOS)

MountlistSample="""\
/dev/sda1 on / type ext4 (rw)
proc on /proc type proc (rw)
sysfs on /sys type sysfs (rw)
devpts on /dev/pts type devpts (rw,gid=5,mode=620)
tmpfs on /dev/shm type tmpfs (rw,rootcontext="system_u:object_r:tmpfs_t:s0")
none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)
/dev/sdb1 on /mnt/resource type ext4 (rw)
"""

class TestCurrOS(unittest.TestCase):
    def test_get_paths(self):
        self.assertNotEquals(None, CurrOS.GetHome())
        self.assertNotEquals(None, CurrOS.GetLibDir())
        self.assertNotEquals(None, CurrOS.GetAgentPidPath())
        self.assertNotEquals(None, CurrOS.GetConfigurationPath())
        self.assertNotEquals(None, CurrOS.GetDvdMountPoint())
        self.assertNotEquals(None, CurrOS.GetOvfEnvPathOnDvd())

    @Mockup(osutil.shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(osutil.shellutil, 'RunSendStdin', MockFunc(retval=[0, '']))
    @Mockup(osutil.fileutil, 'SetFileContents', MockFunc())
    @Mockup(osutil.fileutil, 'GetFileContents', MockFunc(retval=''))
    @Mockup(osutil.fileutil, 'ChangeMod', MockFunc())
    def test_update_user_account(self):
        CurrOS.UpdateUserAccount('api', 'api')
        CurrOS.DeleteAccount('api')

    @Mockup(osutil.fileutil, 'GetFileContents', MockFunc(retval='root::::'))
    @Mockup(osutil.fileutil, 'ReplaceFileContentsAtomic', MockFunc())
    def test_delete_root_password(self):
        CurrOS.DeleteRootPassword()
        self.assertEquals('root:*LOCK*:14600::::::',
                          fileutil.ReplaceFileContentsAtomic.args[1])
  
    def test_wireserver_endpoint(self):
        if os.path.isfile('/tmp/wireserver'):
            os.remove('/tmp/wireserver')
        CurrOS.SetWireServerEndpoint("wireserver")
        endpoint = CurrOS.GetWireServerEndpoint()
        self.assertEquals('wireserver', endpoint)

    def test_cert_operation(self):
        if os.path.isfile('/tmp/test.prv'):
            os.remove('/tmp/test.prv')
        shutil.copyfile(os.path.join(env.test_root, 'test.prv'), 
                        '/tmp/test.prv')
        if os.path.isfile('/tmp/test.crt'):
            os.remove('/tmp/test.crt')
        shutil.copyfile(os.path.join(env.test_root, 'test.crt'), 
                        '/tmp/test.crt')
        pub1 = CurrOS.GetPubKeyFromPrv('/tmp/test.prv')
        pub2 = CurrOS.GetPubKeyFromCrt('/tmp/test.crt')
        self.assertEquals(pub1, pub2)
        thumbprint = CurrOS.GetThumbprintFromCrt('/tmp/test.crt')
        self.assertEquals('33B0ABCE4673538650971C10F7D7397E71561F35', thumbprint)

    def test_selinux(self):
        if not CurrOS.IsSelinuxSystem():
            return
        isRunning = CurrOS.IsSelinuxRunning()
        if not CurrOS.IsSelinuxRunning():
            CurrOS.SetSelinuxEnforce(0)
            self.assertEquals(False, CurrOS.IsSelinuxRunning())
            CurrOS.SetSelinuxEnforce(1)
            self.assertEquals(True, CurrOS.IsSelinuxRunning())
        if os.path.isfile('/tmp/abc'):
            os.remove('/tmp/abc')
        fileutil.SetFileContents('/tmp/abc', '')
        CurrOS.SetSelinuxContext('/tmp/abc','unconfined_u:object_r:ssh_home_t:s')
        CurrOS.SetSelinuxEnforce(1 if isRunning else 0)

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(fileutil, 'SetFileContents', MockFunc())
    def test_network_operation(self):
        CurrOS.StartNetwork()
        CurrOS.OpenPortForDhcp()
        CurrOS.GenerateTransportCert()
        mac = CurrOS.GetMacAddress()
        self.assertNotEquals(None, mac)
        CurrOS.IsMissingDefaultRoute()
        CurrOS.SetBroadcastRouteForDhcp('api')
        CurrOS.RemoveBroadcastRouteForDhcp('api')
        CurrOS.RouteAdd('', '', '')
        CurrOS.GetDhcpProcessId()
        CurrOS.SetHostname('api')
        CurrOS.PublishHostname('api')
   
    @Mockup(CurrOS, 'GetHome', MockFunc(retval='/tmp/home'))
    def test_deploy_key(self):
        if os.path.isdir('/tmp/home'):
            shutil.rmtree('/tmp/home')
        user = shellutil.RunGetOutput('whoami')[1].strip()
        CurrOS.DeploySshKeyPair(user, 'test', '$HOME/.ssh/id_rsa')
        CurrOS.DeploySshPublicKey(user, 'test', '$HOME/.ssh/authorized_keys')
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa.pub'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/authorized_keys'))

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(CurrOS, 'GetSshdConfigPath', MockFunc(retval='/tmp/sshd_config'))
    def test_ssh_operation(self):
        CurrOS.RegenerateSshHostkey('rsa')
        shellutil.RunGetOutput.retval=[0, 
                                       '2048 f1:fe:14:66:9d:46:9a:60:8b:8c:'
                                       '80:43:39:1c:20:9e  root@api (RSA)']
        thumbprint = CurrOS.GetSshHostKeyThumbprint('rsa')
        self.assertEquals('f1fe14669d469a608b8c8043391c209e', thumbprint)
        sshdConfig = CurrOS.GetSshdConfigPath()
        self.assertEquals('/tmp/sshd_config', sshdConfig)
        if os.path.isfile(sshdConfig):
            os.remove(sshdConfig)
        shutil.copyfile(os.path.join(env.test_root, 'sshd_config'), sshdConfig)
        CurrOS.SetSshClientAliveInterval()
        CurrOS.ConfigSshd(True)
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'PasswordAuthentication no'))
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'ChallengeResponseAuthentication no'))
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'ClientAliveInterval 180'))

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(CurrOS, 'GetDvdMountPoint', MockFunc(retval='/tmp/cdrom'))
    def test_mount(self):
        CurrOS.MountDvd()
        CurrOS.UmountDvd()
        mountPoint = CurrOS._GetMountPoint(MountlistSample, '/dev/sda')
        self.assertNotEquals(None, mountPoint)

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(fileutil, 'CreateDir', MockFunc())
    @Mockup(CurrOS, 'DeviceForIdePort', MockFunc(retval='api'))
    def test_resource_disk(self):
        CurrOS.MountResourceDisk('/tmp/resource', 'ext3')

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    def test_swap(self):
        CurrOS.CreateSwapSpace('/tmp', 1024)    

    def test_getdvd(self):
        CurrOS.GetDvdDevice()

if __name__ == '__main__':
    unittest.main()
