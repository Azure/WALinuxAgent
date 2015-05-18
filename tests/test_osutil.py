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
from tests.tools import *
import uuid
import unittest
import os
import shutil
import time
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.osutil as osutil
from azureguestagent.utils.osutil import CurrOSUtil
import azureguestagent.conf as conf
import test

class TestCurrOSUtil(unittest.TestCase):
    def test_current_distro(self):
        self.assertNotEquals(None, CurrOSUtil)

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
#class TestCurrOS(object):
    def test_get_paths(self):
        self.assertNotEquals(None, CurrOSUtil.GetHome())
        self.assertNotEquals(None, CurrOSUtil.GetLibDir())
        self.assertNotEquals(None, CurrOSUtil.GetAgentPidPath())
        self.assertNotEquals(None, CurrOSUtil.GetConfigurationPath())
        self.assertNotEquals(None, CurrOSUtil.GetDvdMountPoint())
        self.assertNotEquals(None, CurrOSUtil.GetOvfEnvPathOnDvd())

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(shellutil, 'RunSendStdin', MockFunc(retval=[0, '']))
    @Mockup(fileutil, 'SetFileContents', MockFunc())
    @Mockup(fileutil, 'GetFileContents', MockFunc(retval=''))
    @Mockup(fileutil, 'ChangeMod', MockFunc())
    def test_update_user_account(self):
        CurrOSUtil.UpdateUserAccount('api', 'api')
        CurrOSUtil.DeleteAccount('api')

    @Mockup(fileutil, 'GetFileContents', MockFunc(retval='root::::'))
    @Mockup(fileutil, 'ReplaceFileContentsAtomic', MockFunc())
    def test_delete_root_password(self):
        CurrOSUtil.DeleteRootPassword()
        self.assertEquals('root:*LOCK*:14600::::::',
                          fileutil.ReplaceFileContentsAtomic.args[1])
 
    def test_cert_operation(self):
        if os.path.isfile('/tmp/test.prv'):
            os.remove('/tmp/test.prv')
        shutil.copyfile(os.path.join(env.test_root, 'test.prv'), 
                        '/tmp/test.prv')
        if os.path.isfile('/tmp/test.crt'):
            os.remove('/tmp/test.crt')
        shutil.copyfile(os.path.join(env.test_root, 'test.crt'), 
                        '/tmp/test.crt')
        pub1 = CurrOSUtil.GetPubKeyFromPrv('/tmp/test.prv')
        pub2 = CurrOSUtil.GetPubKeyFromCrt('/tmp/test.crt')
        self.assertEquals(pub1, pub2)
        thumbprint = CurrOSUtil.GetThumbprintFromCrt('/tmp/test.crt')
        self.assertEquals('33B0ABCE4673538650971C10F7D7397E71561F35', thumbprint)

    def test_selinux(self):
        if not CurrOSUtil.IsSelinuxSystem():
            return
        isRunning = CurrOSUtil.IsSelinuxRunning()
        if not CurrOSUtil.IsSelinuxRunning():
            CurrOSUtil.SetSelinuxEnforce(0)
            self.assertEquals(False, CurrOSUtil.IsSelinuxRunning())
            CurrOSUtil.SetSelinuxEnforce(1)
            self.assertEquals(True, CurrOSUtil.IsSelinuxRunning())
        if os.path.isfile('/tmp/abc'):
            os.remove('/tmp/abc')
        fileutil.SetFileContents('/tmp/abc', '')
        CurrOSUtil.SetSelinuxContext('/tmp/abc','unconfined_u:object_r:ssh_home_t:s')
        CurrOSUtil.SetSelinuxEnforce(1 if isRunning else 0)

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(fileutil, 'SetFileContents', MockFunc())
    def test_network_operation(self):
        CurrOSUtil.StartNetwork()
        CurrOSUtil.OpenPortForDhcp()
        CurrOSUtil.GenerateTransportCert()
        mac = CurrOSUtil.GetMacAddress()
        self.assertNotEquals(None, mac)
        CurrOSUtil.IsMissingDefaultRoute()
        CurrOSUtil.SetBroadcastRouteForDhcp('api')
        CurrOSUtil.RemoveBroadcastRouteForDhcp('api')
        CurrOSUtil.RouteAdd('', '', '')
        CurrOSUtil.GetDhcpProcessId()
        CurrOSUtil.SetHostname('api')
        CurrOSUtil.PublishHostname('api')
   
    @Mockup(CurrOSUtil, 'GetHome', MockFunc(retval='/tmp/home'))
    def test_deploy_key(self):
        if os.path.isdir('/tmp/home'):
            shutil.rmtree('/tmp/home')
        user = shellutil.RunGetOutput('whoami')[1].strip()
        CurrOSUtil.DeploySshKeyPair(user, 'test', '$HOME/.ssh/id_rsa')
        CurrOSUtil.DeploySshPublicKey(user, 'test', '$HOME/.ssh/authorized_keys')
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa.pub'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/authorized_keys'))

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(CurrOSUtil, 'GetSshdConfigPath', MockFunc(retval='/tmp/sshd_config'))
    def test_ssh_operation(self):
        shellutil.RunGetOutput.retval=[0, 
                                       '2048 f1:fe:14:66:9d:46:9a:60:8b:8c:'
                                       '80:43:39:1c:20:9e  root@api (RSA)']
        sshdConfig = CurrOSUtil.GetSshdConfigPath()
        self.assertEquals('/tmp/sshd_config', sshdConfig)
        if os.path.isfile(sshdConfig):
            os.remove(sshdConfig)
        shutil.copyfile(os.path.join(env.test_root, 'sshd_config'), sshdConfig)
        CurrOSUtil.SetSshClientAliveInterval()
        CurrOSUtil.ConfigSshd(True)
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'PasswordAuthentication no'))
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'ChallengeResponseAuthentication no'))
        self.assertTrue(simple_file_grep(sshdConfig, 
                                         'ClientAliveInterval 180'))

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(CurrOSUtil, 'GetDvdMountPoint', MockFunc(retval='/tmp/cdrom'))
    def test_mount(self):
        CurrOSUtil.MountDvd()
        CurrOSUtil.UmountDvd()
        mountPoint = CurrOSUtil._GetMountPoint(MountlistSample, '/dev/sda')
        self.assertNotEquals(None, mountPoint)

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    @Mockup(fileutil, 'CreateDir', MockFunc())
    @Mockup(CurrOSUtil, 'DeviceForIdePort', MockFunc(retval='api'))
    def test_resource_disk(self):
        CurrOSUtil.MountResourceDisk('/tmp/resource', 'ext3')

    @Mockup(shellutil, 'RunGetOutput', MockFunc(retval=[0, '']))
    def test_swap(self):
        CurrOSUtil.CreateSwapSpace('/tmp', 1024)    

    def test_getdvd(self):
        CurrOSUtil.GetDvdDevice()

if __name__ == '__main__':
    unittest.main()
