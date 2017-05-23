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

import mock
import os.path

from azurelinuxagent.common.conf import *

from tests.tools import *


class TestConf(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.conf = ConfigurationProvider()
        load_conf_from_file(
                os.path.join(data_dir, "test_waagent.conf"),
                self.conf)

    def test_key_value_handling(self):
        self.assertEqual("Value1", self.conf.get("FauxKey1", "Bad"))
        self.assertEqual("Value2 Value2", self.conf.get("FauxKey2", "Bad"))

    def test_get_ssh_dir(self):
        self.assertTrue(get_ssh_dir(self.conf).startswith("/notareal/path"))

    def test_get_sshd_conf_file_path(self):
        self.assertTrue(get_sshd_conf_file_path(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_glob(self):
        self.assertTrue(get_ssh_key_glob(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_private_path(self):
        self.assertTrue(get_ssh_key_private_path(
            self.conf).startswith("/notareal/path"))

    def test_get_ssh_key_public_path(self):
        self.assertTrue(get_ssh_key_public_path(
            self.conf).startswith("/notareal/path"))

    def test_get_fips_enabled(self):
        self.assertTrue(get_fips_enabled(self.conf))

    def test_get_provision_cloudinit(self):
        self.assertTrue(get_provision_cloudinit(self.conf))
