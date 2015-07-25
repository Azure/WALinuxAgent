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

import tests.env as env
from tests.tools import *
import uuid
import unittest
import os
import shutil
import time
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.conf as conf
from azurelinuxagent.utils.osutil import OSUTIL, OSUtilError
import test

class TestOSUtil(unittest.TestCase):
    def test_current_distro(self):
        self.assertNotEquals(None, OSUTIL)

mount_list_sample="""\
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
        self.assertNotEquals(None, OSUTIL.get_home())
        self.assertNotEquals(None, OSUTIL.get_lib_dir())
        self.assertNotEquals(None, OSUTIL.get_agent_pid_file_path())
        self.assertNotEquals(None, OSUTIL.get_conf_file_path())
        self.assertNotEquals(None, OSUTIL.get_dvd_mount_point())
        self.assertNotEquals(None, OSUTIL.get_ovf_env_file_path_on_dvd())

    @mock(fileutil, 'write_file', MockFunc())
    @mock(fileutil, 'append_file', MockFunc())
    @mock(fileutil, 'chmod', MockFunc())
    @mock(fileutil, 'read_file', MockFunc(retval=''))
    @mock(shellutil, 'run', MockFunc())
    @mock(shellutil, 'run_get_output', MockFunc(retval=[0, '']))
    def test_update_user_account(self):
        OSUTIL.useradd('foo')
        OSUTIL.chpasswd('foo', 'bar')
        OSUTIL.del_account('foo')

    @mock(fileutil, 'read_file', MockFunc(retval='root::::'))
    @mock(fileutil, 'write_file', MockFunc())
    def test_delete_root_password(self):
        OSUTIL.del_root_password()
        self.assertEquals('root:*LOCK*:14600::::::',
                          fileutil.write_file.args[1])
 
    def test_cert_operation(self):
        if os.path.isfile('/tmp/test.prv'):
            os.remove('/tmp/test.prv')
        shutil.copyfile(os.path.join(env.test_root, 'test.prv'), 
                        '/tmp/test.prv')
        if os.path.isfile('/tmp/test.crt'):
            os.remove('/tmp/test.crt')
        shutil.copyfile(os.path.join(env.test_root, 'test.crt'), 
                        '/tmp/test.crt')
        pub1 = OSUTIL.get_pubkey_from_prv('/tmp/test.prv')
        pub2 = OSUTIL.get_pubkey_from_crt('/tmp/test.crt')
        self.assertEquals(pub1, pub2)
        thumbprint = OSUTIL.get_thumbprint_from_crt('/tmp/test.crt')
        self.assertEquals('33B0ABCE4673538650971C10F7D7397E71561F35', thumbprint)

    def test_selinux(self):
        if not OSUTIL.is_selinux_system():
            return
        isrunning = OSUTIL.is_selinux_enforcing()
        if not OSUTIL.is_selinux_enforcing():
            OSUTIL.set_selinux_enforce(0)
            self.assertEquals(False, OSUTIL.is_selinux_enforcing())
            OSUTIL.set_selinux_enforce(1)
            self.assertEquals(True, OSUTIL.is_selinux_enforcing())
        if os.path.isfile('/tmp/abc'):
            os.remove('/tmp/abc')
        fileutil.write_file('/tmp/abc', '')
        OSUTIL.set_selinux_context('/tmp/abc','unconfined_u:object_r:ssh_home_t:s')
        OSUTIL.set_selinux_enforce(1 if isrunning else 0)

    @mock(shellutil, 'run_get_output', MockFunc(retval=[0, '']))
    @mock(fileutil, 'write_file', MockFunc())
    def test_network_operation(self):
        OSUTIL.start_network()
        OSUTIL.allow_dhcp_broadcast()
        OSUTIL.gen_transport_cert()
        mac = OSUTIL.get_mac_addr()
        self.assertNotEquals(None, mac)
        OSUTIL.is_missing_default_route()
        OSUTIL.set_route_for_dhcp_broadcast('api')
        OSUTIL.remove_route_for_dhcp_broadcast('api')
        OSUTIL.route_add('', '', '')
        OSUTIL.get_dhcp_pid()
        OSUTIL.set_hostname('api')
        OSUTIL.publish_hostname('api')
   
    @mock(OSUTIL, 'get_home', MockFunc(retval='/tmp/home'))
    @mock(OSUTIL, 'get_pubkey_from_prv', MockFunc(retval=''))
    @mock(fileutil, 'chowner', MockFunc())
    def test_deploy_key(self):
        if os.path.isdir('/tmp/home'):
            shutil.rmtree('/tmp/home')
        fileutil.write_file('/tmp/foo.prv', '')
        OSUTIL.deploy_ssh_keypair("foo", ('$HOME/.ssh/id_rsa', 'foo'))
        OSUTIL.deploy_ssh_pubkey("foo", ('$HOME/.ssh/authorized_keys', None, 
                                         'ssh-rsa asdf'))
        OSUTIL.deploy_ssh_pubkey("foo", ('$HOME/.ssh/authorized_keys', 'foo', 
                                         'ssh-rsa asdf'))
        self.assertRaises(OSUtilError, OSUTIL.deploy_ssh_pubkey, "foo", 
                         ('$HOME/.ssh/authorized_keys', 'foo','hehe-rsa asdf'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/id_rsa.pub'))
        self.assertTrue(os.path.isfile('/tmp/home/.ssh/authorized_keys'))

    @mock(shellutil, 'run_get_output', MockFunc(retval=[0, '']))
    @mock(OSUTIL, 'get_sshd_conf_file_path', MockFunc(retval='/tmp/sshd_config'))
    def test_ssh_operation(self):
        shellutil.run_get_output.retval=[0, 
                                       '2048 f1:fe:14:66:9d:46:9a:60:8b:8c:'
                                       '80:43:39:1c:20:9e  root@api (RSA)']
        sshd_conf = OSUTIL.get_sshd_conf_file_path()
        self.assertEquals('/tmp/sshd_config', sshd_conf)
        if os.path.isfile(sshd_conf):
            os.remove(sshd_conf)
        shutil.copyfile(os.path.join(env.test_root, 'sshd_config'), sshd_conf)
        OSUTIL.set_ssh_client_alive_interval()
        OSUTIL.conf_sshd(True)
        self.assertTrue(simple_file_grep(sshd_conf, 
                                         'PasswordAuthentication no'))
        self.assertTrue(simple_file_grep(sshd_conf, 
                                         'ChallengeResponseAuthentication no'))
        self.assertTrue(simple_file_grep(sshd_conf, 
                                         'ClientAliveInterval 180'))

    @mock(shellutil, 'run_get_output', MockFunc(retval=[0, '']))
    @mock(OSUTIL, 'get_dvd_device', MockFunc(retval=[0, 'abc']))
    @mock(OSUTIL, 'get_mount_point', MockFunc(retval='/tmp/cdrom'))
    def test_mount(self):
        OSUTIL.mount_dvd()
        OSUTIL.umount_dvd()
        mount_point = OSUTIL.get_mount_point(mount_list_sample, '/dev/sda')
        self.assertNotEquals(None, mount_point)

    def test_getdvd(self):
        fileutil.write_file("/tmp/sr0", '')
        OSUTIL.get_dvd_device(dev_dir='/tmp')

if __name__ == '__main__':
    unittest.main()
