# Copyright 2018 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import os.path

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, data_dir, patch


class TestConf(AgentTestCase):
    # Note:
    # -- These values *MUST* match those from data/test_waagent.conf
    EXPECTED_CONFIGURATION = {
        "Extensions.Enabled": True,
        "Provisioning.Agent": "auto",
        "Provisioning.DeleteRootPassword": True,
        "Provisioning.RegenerateSshHostKeyPair": True,
        "Provisioning.SshHostKeyPairType": "rsa",
        "Provisioning.MonitorHostName": True,
        "Provisioning.DecodeCustomData": False,
        "Provisioning.ExecuteCustomData": False,
        "Provisioning.PasswordCryptId": '6',
        "Provisioning.PasswordCryptSaltLength": 10,
        "Provisioning.AllowResetSysUser": False,
        "ResourceDisk.Format": True,
        "ResourceDisk.Filesystem": "ext4",
        "ResourceDisk.MountPoint": "/mnt/resource",
        "ResourceDisk.EnableSwap": False,
        "ResourceDisk.EnableSwapEncryption": False,
        "ResourceDisk.SwapSizeMB": 0,
        "ResourceDisk.MountOptions": None,
        "Logs.Verbose": False,
        "OS.EnableFIPS": True,
        "OS.RootDeviceScsiTimeout": '300',
        "OS.OpensslPath": '/usr/bin/openssl',
        "OS.SshClientAliveInterval": 42,
        "OS.SshDir": "/notareal/path",
        "HttpProxy.Host": None,
        "HttpProxy.Port": None,
        "DetectScvmmEnv": False,
        "Lib.Dir": "/var/lib/waagent",
        "DVD.MountPoint": "/mnt/cdrom/secure",
        "Pid.File": "/var/run/waagent.pid",
        "Extension.LogDir": "/var/log/azure",
        "OS.HomeDir": "/home",
        "OS.EnableRDMA": False,
        "OS.UpdateRdmaDriver": False,
        "OS.CheckRdmaDriver": False,
        "AutoUpdate.Enabled": True,
        "AutoUpdate.GAFamily": "Prod",
        "EnableOverProvisioning": True,
        "OS.AllowHTTP": False,
        "OS.EnableFirewall": False,
        "CGroups.EnforceLimits": False,
        "CGroups.Excluded": "customscript,runcommand",
    }

    def setUp(self):
        AgentTestCase.setUp(self)
        self.conf = conf.ConfigurationProvider()
        conf.load_conf_from_file(
                os.path.join(data_dir, "test_waagent.conf"),
                self.conf)

    def test_key_value_handling(self):
        self.assertEqual("Value1", self.conf.get("FauxKey1", "Bad"))
        self.assertEqual("Value2 Value2", self.conf.get("FauxKey2", "Bad"))
        self.assertEqual("delalloc,rw,noatime,nobarrier,users,mode=777", self.conf.get("FauxKey3", "Bad"))

    def test_get_ssh_dir(self):
        self.assertTrue(conf.get_ssh_dir(self.conf).startswith("/notareal/path"))

    def test_get_sshd_conf_file_path(self):
        self.assertTrue(conf.get_sshd_conf_file_path(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_glob(self):
        self.assertTrue(conf.get_ssh_key_glob(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_private_path(self):
        self.assertTrue(conf.get_ssh_key_private_path(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_public_path(self):
        self.assertTrue(conf.get_ssh_key_public_path(
            self.conf).startswith("/notareal/path"))

    def test_get_fips_enabled(self):
        self.assertTrue(conf.get_fips_enabled(self.conf))

    def test_get_provision_agent(self):
        self.assertTrue(conf.get_provisioning_agent(self.conf) == 'auto')

    def test_get_configuration(self):
        configuration = conf.get_configuration(self.conf)
        self.assertTrue(len(configuration.keys()) > 0)
        for k in TestConf.EXPECTED_CONFIGURATION.keys():
            self.assertEqual(
                TestConf.EXPECTED_CONFIGURATION[k],
                configuration[k],
                k)

    def test_get_agent_disabled_file_path(self):
        self.assertEqual(conf.get_disable_agent_file_path(self.conf),
                         os.path.join(self.tmp_dir, conf.DISABLE_AGENT_FILE))

    def test_write_agent_disabled(self):
        """
        Test writing disable_agent is empty
        """
        from azurelinuxagent.pa.provision.default import ProvisionHandler

        disable_file_path = conf.get_disable_agent_file_path(self.conf)
        self.assertFalse(os.path.exists(disable_file_path))
        ProvisionHandler.write_agent_disabled()
        self.assertTrue(os.path.exists(disable_file_path))
        self.assertEqual('', fileutil.read_file(disable_file_path))

    def test_get_extensions_enabled(self):
        self.assertTrue(conf.get_extensions_enabled(self.conf))

    @patch('azurelinuxagent.common.conf.ConfigurationProvider.get')
    def assert_get_cgroups_excluded(self, patch_get, config, expected_value):
        patch_get.return_value = config
        self.assertEqual(expected_value, conf.get_cgroups_excluded(self.conf))

    def test_get_cgroups_excluded(self):
        self.assert_get_cgroups_excluded(config=None, # pylint: disable=no-value-for-parameter
                                         expected_value=[])

        self.assert_get_cgroups_excluded(config='', # pylint: disable=no-value-for-parameter
                                         expected_value=[])

        self.assert_get_cgroups_excluded(config='  ', # pylint: disable=no-value-for-parameter
                                         expected_value=[])

        self.assert_get_cgroups_excluded(config='  ,  ,,  ,', # pylint: disable=no-value-for-parameter
                                         expected_value=[])

        standard_values = ['customscript', 'runcommand']
        self.assert_get_cgroups_excluded(config='CustomScript, RunCommand', # pylint: disable=no-value-for-parameter
                                         expected_value=standard_values)

        self.assert_get_cgroups_excluded(config='customScript, runCommand  , , ,,', # pylint: disable=no-value-for-parameter
                                         expected_value=standard_values)

        self.assert_get_cgroups_excluded(config='  customscript,runcommand  ', # pylint: disable=no-value-for-parameter
                                         expected_value=standard_values)

        self.assert_get_cgroups_excluded(config='customscript,, runcommand', # pylint: disable=no-value-for-parameter
                                         expected_value=standard_values)

        self.assert_get_cgroups_excluded(config=',,customscript ,runcommand', # pylint: disable=no-value-for-parameter
                                         expected_value=standard_values)
