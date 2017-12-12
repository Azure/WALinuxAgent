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

import json
import socket

import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ProvisionError
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

    @patch('azurelinuxagent.common.conf.get_provision_enabled',
        return_value=False)
    def test_provisioning_is_skipped_when_not_enabled(self, mock_conf):
        ph = ProvisionHandler()
        ph.osutil = DefaultOSUtil()
        ph.osutil.get_instance_id = Mock(
                        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')

        ph.is_provisioned = Mock()
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        ph.run()

        ph.is_provisioned.assert_not_called()
        ph.report_ready.assert_called_once()
        ph.write_provisioned.assert_called_once()

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
        ph.osutil.is_current_instance_id = Mock(return_value=True)
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        ph.osutil.is_current_instance_id.assert_called_once()
        deprovision_handler.run_changed_unique_id.assert_not_called()

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_is_provisioned_not_deprovisioned(self,
            mock_deprovision, mock_read, mock_isfile):

        ph = ProvisionHandler()
        ph.osutil = Mock()
        ph.osutil.is_current_instance_id = Mock(return_value=False)
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        ph.osutil.is_current_instance_id.assert_called_once()
        deprovision_handler.run_changed_unique_id.assert_called_once()

    @distros()
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    def test_provision_telemetry_success(self, mock_util, distro_name, distro_version,
                       distro_full_name):
        """
        Assert that the agent issues two telemetry messages as part of a
        successful provisioning.

         1. Provision
         2. GuestState
        """
        ph = get_provision_handler(distro_name, distro_version,
                                   distro_full_name)
        ph.report_event = MagicMock()
        ph.reg_ssh_host_key = MagicMock(return_value='--thumprint--')

        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")

        ph.osutil = mock_osutil
        ph.protocol_util.osutil = mock_osutil
        ph.protocol_util.get_protocol_by_file = MagicMock()
        ph.protocol_util.get_protocol = MagicMock()

        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)

        ph.run()

        call1 = call("Provision succeeded", duration=ANY, is_success=True)
        call2 = call(ANY, is_success=True, operation=WALAEventOperation.GuestState)
        ph.report_event.assert_has_calls([call1, call2])

        args, kwargs = ph.report_event.call_args_list[1]
        guest_state_json = json.loads(args[0])
        self.assertTrue(1 <= guest_state_json['cpu'])
        self.assertTrue(1 <= guest_state_json['mem'])
        self.assertEqual(socket.gethostname(), guest_state_json['hostname'])

    @distros()
    @patch(
        'azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    def test_provision_telemetry_fail(self, mock_util, distro_name,
                                         distro_version,
                                         distro_full_name):
        """
        Assert that the agent issues one telemetry message as part of a
        failed provisioning.

         1. Provision
        """
        ph = get_provision_handler(distro_name, distro_version,
                                   distro_full_name)
        ph.report_event = MagicMock()
        ph.reg_ssh_host_key = MagicMock(side_effect=ProvisionError(
            "--unit-test--"))

        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")

        ph.osutil = mock_osutil
        ph.protocol_util.osutil = mock_osutil
        ph.protocol_util.get_protocol_by_file = MagicMock()
        ph.protocol_util.get_protocol = MagicMock()

        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)

        ph.run()
        ph.report_event.assert_called_once_with(
            "[ProvisionError] --unit-test--")


if __name__ == '__main__':
    unittest.main()

