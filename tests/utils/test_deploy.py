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

from __future__ import print_function

import json
import os.path
import shutil

from azurelinuxagent.common.utils.deploy import *
from azurelinuxagent.common.utils.fileutil import *
from tests.tools import *


UBUNTU_PLATFORMS = [
    ["Ubuntu", "14.04", ""],
    ["Ubuntu", "14.10", ""],
    ["Ubuntu", "15.10", ""],
    ["Ubuntu", "15.10", "Snappy Ubuntu Core"],
    ["Ubuntu", "16.04", ""],
    ["Ubuntu", "16.10", ""]
]

FEDORA_PLATFORMS = [
    ["Oracle", "7.2", ""],
    ["Oracle", "7.3", ""],

    ["Red Hat", "7.0", ""],
    ["Red Hat", "7.3", ""]
]

UNSUPPORTED_PLATFORMS = [
    ["coreos", "", ""],

    ["debian", "6.0", ""],

    ["suse", "12", "SUSE Linux Enterprise Server"],
    ["suse", "13.2", "openSUSE"],
    ["suse", "11", "SUSE Linux Enterprise Server"],
    ["suse", "13.1", "openSUSE"]
]

class TestFamily(AgentTestCase):

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_creation(self, mock_distribution, mock_osutil):
        self.assertRaises(TypeError, Family)
        self.assertRaises(Exception, Family, None, {})
        self.assertRaises(Exception, Family, "name", None)

        data = json.loads(load_data("deploy.json"))
        family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])

        self.assertEqual(family.name, "ubuntu-x64")
        self.assertTrue(family._is_supported)
        self.assertEqual(family._partition, 85)
        self.assertEqual(family._versions, ['^Ubuntu,(1[4-9]|2[0-9])\\.\\d+,.*$'])

    @patch('azurelinuxagent.common.utils.deploy.get_osutil')
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_architecture_matches(self, mock_distribution, mock_osutil):
        data = json.loads(load_data("deploy.json"))

        mock_osutil.is_64bit = True
        family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])
        self.assertTrue(family._is_supported)

        mock_osutil.is_64bit = False
        family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])
        self.assertTrue(family._is_supported)

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_in_partition(self, mock_distribution, mock_osutil):
        data = json.loads(load_data("deploy.json"))
        family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])

        self.assertEqual(family._partition, 85)
        for i in range(0, 100):
            self.assertEqual(i < family._partition, family.in_partition(i))

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution')
    def test_version_matches(self, mock_distribution, mock_osutil):
        data = json.loads(load_data("deploy.json"))

        for d in UBUNTU_PLATFORMS:
            mock_distribution.return_value = d
            family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])
            self.assertTrue(family._is_supported)

        for d in FEDORA_PLATFORMS:
            mock_distribution.return_value = d
            family = Family("fedora-x64", data["families"]["fedora-x64"])
            self.assertTrue(family._is_supported)

        for d in UNSUPPORTED_PLATFORMS:
            mock_distribution.return_value = d
            family = Family("ubuntu-x64", data["families"]["ubuntu-x64"])
            self.assertFalse(family._is_supported)
            family = Family("fedora-x64", data["families"]["fedora-x64"])
            self.assertFalse(family._is_supported)


class TestDeploy(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        shutil.copy(os.path.join(data_dir, DEPLOY_FILE), self.tmp_dir)

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_creation(self, mock_distribution, mock_osutil):
        self.assertRaises(Exception, Deploy, "foobarbaz")

        deploy = Deploy()
        self.assertEqual(0, len(deploy.blacklisted))
        self.assertEqual(0, len(deploy._families))
        self.assertEqual(None, deploy._family)
        self.assertEqual(None, deploy.family)

        deploy = Deploy(self.tmp_dir)
        self.assertTrue(len(deploy.blacklisted) > 0)
        self.assertTrue(len(deploy._families) > 0)
        self.assertFalse(deploy._family is None)
        self.assertTrue(len(deploy.family) > 0)

        os.remove(os.path.join(self.tmp_dir, DEPLOY_FILE))
        deploy = Deploy(self.tmp_dir)
        self.assertEqual(0, len(deploy.blacklisted))
        self.assertEqual(0, len(deploy._families))
        self.assertEqual(None, deploy._family)
        self.assertEqual(None, deploy.family)

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_in_safe_deployment_mode(self, mock_distribution, mock_osutil):
        deploy = Deploy(self.tmp_dir)
        self.assertTrue(deploy.in_safe_deployment_mode)

        os.remove(os.path.join(self.tmp_dir, DEPLOY_FILE))
        deploy = Deploy(self.tmp_dir)
        self.assertFalse(deploy.in_safe_deployment_mode)

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_in_partition(self, mock_distribution, mock_osutil):
        deploy = Deploy(self.tmp_dir)
        self.assertTrue(deploy.in_partition(84))
        self.assertFalse(deploy.in_partition(85))

        os.remove(os.path.join(self.tmp_dir, DEPLOY_FILE))
        deploy = Deploy(self.tmp_dir)
        for i in range(0, 100):
            self.assertTrue(deploy.in_partition(i))

    @patch('azurelinuxagent.common.utils.deploy.get_osutil', return_value=Mock(is_64bit=True))
    @patch('platform.linux_distribution', return_value=('Ubuntu', '16.10', 'yakkety'))
    def test_mark_deployed(self, mock_distribution, mock_osutil):
        deploy = Deploy(self.tmp_dir)

        before = os.path.join(self.tmp_dir, DEPLOY_FILE)
        after = os.path.join(self.tmp_dir, DEPLOYED_FILE)

        self.assertTrue(os.path.isfile(before))
        self.assertFalse(os.path.exists(after))
        self.assertFalse(deploy.is_deployed)

        deploy.mark_deployed()

        self.assertFalse(os.path.exists(before))
        self.assertTrue(os.path.isfile(after))
        self.assertTrue(deploy.is_deployed)

        deploy = Deploy(self.tmp_dir)
        self.assertTrue(deploy.in_safe_deployment_mode)
        self.assertTrue(deploy.is_deployed)

if __name__ == '__main__':
    unittest.main()
