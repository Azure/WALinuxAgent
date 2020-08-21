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

import os
import re
import tempfile
import unittest

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ProvisionError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.protocol.util import OVF_FILE_NAME
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.pa.provision.cloudinit import CloudInitProvisionHandler
from azurelinuxagent.pa.provision.default import ProvisionHandler
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, distros, load_data, MagicMock, Mock, patch


class TestProvision(AgentTestCase):
 
    @distros("redhat")
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    def test_provision(self, mock_util, distro_name, distro_version, distro_full_name): # pylint: disable=unused-argument
        provision_handler = get_provision_handler(distro_name, distro_version,
                                                  distro_full_name)
        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")
        
        provision_handler.osutil = mock_osutil
        provision_handler.protocol_util.osutil = mock_osutil
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
    def test_provisioning_is_skipped_when_not_enabled(self, mock_conf): # pylint: disable=unused-argument
        ph = ProvisionHandler() # pylint: disable=invalid-name
        ph.osutil = DefaultOSUtil()
        ph.osutil.get_instance_id = Mock(
                        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')

        ph.is_provisioned = Mock()
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        ph.run()

        self.assertEqual(0, ph.is_provisioned.call_count)
        self.assertEqual(1, ph.report_ready.call_count)
        self.assertEqual(1, ph.write_provisioned.call_count)

    @patch('os.path.isfile', return_value=False)
    def test_is_provisioned_not_provisioned(self, mock_isfile): # pylint: disable=unused-argument
        ph = ProvisionHandler() # pylint: disable=invalid-name
        self.assertFalse(ph.is_provisioned())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_is_provisioned_is_provisioned(self,
            mock_deprovision, mock_read, mock_isfile): # pylint: disable=unused-argument

        ph = ProvisionHandler() # pylint: disable=invalid-name
        ph.osutil = Mock()
        ph.osutil.is_current_instance_id = Mock(return_value=True)
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        self.assertEqual(1, ph.osutil.is_current_instance_id.call_count)
        self.assertEqual(0, deprovision_handler.run_changed_unique_id.call_count)

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_is_provisioned_not_deprovisioned(self,
            mock_deprovision, mock_read, mock_isfile): # pylint: disable=unused-argument

        ph = ProvisionHandler() # pylint: disable=invalid-name
        ph.osutil = Mock()
        ph.osutil.is_current_instance_id = Mock(return_value=False)
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.is_provisioned())
        self.assertEqual(1, ph.osutil.is_current_instance_id.call_count)
        self.assertEqual(1, deprovision_handler.run_changed_unique_id.call_count)

    @distros()
    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    def test_provision_telemetry_pga_false(self,
                                           distro_name,
                                           distro_version,
                                           distro_full_name, _):
        """
        ProvisionGuestAgent flag is 'false'
        """
        self._provision_test(distro_name, # pylint: disable=no-value-for-parameter
                             distro_version,
                             distro_full_name,
                             OVF_FILE_NAME,
                             'false',
                             True)

    @distros()
    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    def test_provision_telemetry_pga_true(self,
                                          distro_name,
                                          distro_version,
                                          distro_full_name, _):
        """
        ProvisionGuestAgent flag is 'true'
        """
        self._provision_test(distro_name, # pylint: disable=no-value-for-parameter
                             distro_version,
                             distro_full_name,
                             'ovf-env-2.xml',
                             'true',
                             True)

    @distros()
    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    def test_provision_telemetry_pga_empty(self,
                                           distro_name,
                                           distro_version,
                                           distro_full_name, _):
        """
        ProvisionGuestAgent flag is ''
        """
        self._provision_test(distro_name, # pylint: disable=no-value-for-parameter
                             distro_version,
                             distro_full_name,
                             'ovf-env-3.xml',
                             'true',
                             False)

    @distros()
    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    def test_provision_telemetry_pga_bad(self,
                                         distro_name,
                                         distro_version,
                                         distro_full_name, _):
        """
        ProvisionGuestAgent flag is 'bad data'
        """
        self._provision_test(distro_name, # pylint: disable=no-value-for-parameter
                             distro_version,
                             distro_full_name,
                             'ovf-env-4.xml',
                             'bad data',
                             True)

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
           return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    @patch('azurelinuxagent.pa.provision.default.ProvisionHandler.write_agent_disabled')
    def _provision_test(self, # pylint: disable=too-many-locals,invalid-name,too-many-arguments
                        distro_name,
                        distro_version,
                        distro_full_name,
                        ovf_file,
                        provisionMessage,
                        expect_success,
                        patch_write_agent_disabled,
                        patch_get_instance_id): # pylint: disable=unused-argument
        """
        Assert that the agent issues two telemetry messages as part of a
        successful provisioning.

         1. Provision
         2. GuestState
        """
        ph = get_provision_handler(distro_name, # pylint: disable=invalid-name
                                   distro_version,
                                   distro_full_name)
        ph.report_event = MagicMock()
        ph.reg_ssh_host_key = MagicMock(return_value='--thumprint--')

        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")

        ph.osutil = mock_osutil
        ph.protocol_util.osutil = mock_osutil
        ph.protocol_util.get_protocol = MagicMock()

        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data(ovf_file)
        fileutil.write_file(ovfenv_file, ovfenv_data)

        ph.run()

        if expect_success:
            self.assertEqual(2, ph.report_event.call_count)
            positional_args, kw_args = ph.report_event.call_args_list[0]
            # [call('Provisioning succeeded (146473.68s)', duration=65, is_success=True)]
            self.assertTrue(re.match(r'Provisioning succeeded \(\d+\.\d+s\)', positional_args[0]) is not None)
            self.assertTrue(isinstance(kw_args['duration'], int))
            self.assertTrue(kw_args['is_success'])

            positional_args, kw_args = ph.report_event.call_args_list[1]
            self.assertTrue(kw_args['operation'] == 'ProvisionGuestAgent')
            self.assertTrue(kw_args['message'] == provisionMessage)
            self.assertTrue(kw_args['is_success'])

            expected_disabled = True if provisionMessage == 'false' else False # pylint: disable=simplifiable-if-expression
            self.assertTrue(patch_write_agent_disabled.call_count == expected_disabled)

        else:
            self.assertEqual(1, ph.report_event.call_count)
            positional_args, kw_args = ph.report_event.call_args_list[0]
            # [call(u'[ProtocolError] Failed to validate OVF: ProvisionGuestAgent not found')]
            self.assertTrue('Failed to validate OVF: ProvisionGuestAgent not found' in positional_args[0])
            self.assertFalse(kw_args['is_success'])

    @distros()
    @patch(
        'azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    @patch('azurelinuxagent.common.conf.get_provisioning_agent', return_value='waagent')
    def test_provision_telemetry_fail(self,
                                      mock_util, # pylint: disable=unused-argument
                                      distro_name,
                                      distro_version,
                                      distro_full_name, _):
        """
        Assert that the agent issues one telemetry message as part of a
        failed provisioning.

         1. Provision
        """
        ph = get_provision_handler(distro_name, distro_version, # pylint: disable=invalid-name
                                   distro_full_name)
        ph.report_event = MagicMock()
        ph.reg_ssh_host_key = MagicMock(side_effect=ProvisionError(
            "--unit-test--"))

        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")

        ph.osutil = mock_osutil
        ph.protocol_util.osutil = mock_osutil
        ph.protocol_util.get_protocol = MagicMock()

        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)

        ph.run()
        positional_args, kw_args = ph.report_event.call_args_list[0] # pylint: disable=unused-variable
        self.assertTrue(re.match(r'Provisioning failed: \[ProvisionError\] --unit-test-- \(\d+\.\d+s\)', positional_args[0]) is not None)

    @patch('azurelinuxagent.pa.provision.default.ProvisionHandler.write_agent_disabled')
    @distros()
    def test_handle_provision_guest_agent(self,
                                          patch_write_agent_disabled,
                                          distro_name,
                                          distro_version,
                                          distro_full_name):
        ph = get_provision_handler(distro_name, # pylint: disable=invalid-name
                                   distro_version,
                                   distro_full_name)

        patch_write_agent_disabled.call_count = 0

        ph.handle_provision_guest_agent(provision_guest_agent='false')
        self.assertEqual(1, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='False')
        self.assertEqual(2, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='FALSE')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent=' ')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent=None)
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='true')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='True')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

        ph.handle_provision_guest_agent(provision_guest_agent='TRUE')
        self.assertEqual(3, patch_write_agent_disabled.call_count)

    @patch(
        'azurelinuxagent.common.conf.get_provisioning_agent',
        return_value='auto'
    )
    @patch(
        'azurelinuxagent.pa.provision.factory.cloud_init_is_enabled',
        return_value=False
    )
    def test_get_provision_handler_config_auto_no_cloudinit(
            self,
            patch_cloud_init_is_enabled, # pylint: disable=unused-argument
            patch_get_provisioning_agent): # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, ProvisionHandler, 'Auto provisioning handler should be waagent if cloud-init is not enabled')

    @patch(
        'azurelinuxagent.common.conf.get_provisioning_agent',
        return_value='waagent'
    )
    @patch(
        'azurelinuxagent.pa.provision.factory.cloud_init_is_enabled',
        return_value=True
    )
    def test_get_provision_handler_config_waagent(
            self,
            patch_cloud_init_is_enabled, # pylint: disable=unused-argument
            patch_get_provisioning_agent): # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, ProvisionHandler, 'Provisioning handler should be waagent if agent is set to waagent')

    @patch(
        'azurelinuxagent.common.conf.get_provisioning_agent',
        return_value='auto'
    )
    @patch(
        'azurelinuxagent.pa.provision.factory.cloud_init_is_enabled',
        return_value=True
    )
    def test_get_provision_handler_config_auto_cloudinit(
            self,
            patch_cloud_init_is_enabled, # pylint: disable=unused-argument
            patch_get_provisioning_agent): # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, CloudInitProvisionHandler, 'Auto provisioning handler should be cloud-init if cloud-init is enabled')

    @patch(
        'azurelinuxagent.common.conf.get_provisioning_agent',
        return_value='cloud-init'
    )
    def test_get_provision_handler_config_cloudinit(
            self,
            patch_get_provisioning_agent): # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, CloudInitProvisionHandler, 'Provisioning handler should be cloud-init if agent is set to cloud-init')


if __name__ == '__main__':
    unittest.main()

