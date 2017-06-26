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

import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.protocol import OVF_FILE_NAME
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.pa.provision.default import ProvisionHandler
from tests.tools import *


class TestProvision(AgentTestCase):
 
    @distros("redhat")
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    def test_provision(self, mock_util, distro_name, distro_version, distro_full_name):
        provision_handler = get_provision_handler(distro_name, distro_version,
                                                  distro_full_name)
        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")
        
        provision_handler.osutil = mock_osutil
        provision_handler.protocol_util.osutil = mock_osutil
        provision_handler.protocol_util.get_protocol_by_file = MagicMock()
        provision_handler.protocol_util.get_protocol = MagicMock()
       
        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)
         
        provision_handler.run()

    def test_customdata(self):
        base64data = 'Q3VzdG9tRGF0YQ=='
        data = DefaultOSUtil().decode_customdata(base64data)
        fileutil.write_file(tempfile.mktemp(), data)

    @patch('os.path.isfile', return_value=False)
    def test_is_provisioned_not_provisioned(self, mock_isfile):
        ph = ProvisionHandler()
        self.assertFalse(ph.is_provisioned())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_is_provisioned_is_provisioned(self,
            mock_deprovision, mock_read, mock_isfile):
        ph = ProvisionHandler()
        ph.osutil = Mock()
        ph.osutil.get_instance_id = \
            Mock(return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        deprovision_handler.run_changed_unique_id.assert_not_called()

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            side_effect=["Value"])
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_is_provisioned_not_deprovisioned(self,
            mock_deprovision, mock_read, mock_isfile):

        ph = ProvisionHandler()
        ph.osutil = Mock()
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        deprovision_handler.run_changed_unique_id.assert_called_once()

if __name__ == '__main__':
    unittest.main()

