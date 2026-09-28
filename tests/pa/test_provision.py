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
import contextlib
import getpass
import os
import re
import unittest

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ProvisionError, OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.common.protocol.util import OVF_FILE_NAME, MAX_RETRY
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.pa.provision.cloudinit import CloudInitProvisionHandler
from azurelinuxagent.pa.provision.default import ProvisionHandler
from azurelinuxagent.common.utils import fileutil
from tests.lib import wire_protocol_data
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.tools import AgentTestCase, distros, load_data, MagicMock, Mock, patch
from tests.lib.mock_wire_protocol import mock_wire_protocol


class TestProvision(AgentTestCase):
 
    @distros("redhat")
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    def test_provision(self, mock_util, distro_name, distro_version, distro_full_name):  # pylint: disable=unused-argument
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
        DefaultOSUtil().decode_customdata(base64data)

    @patch('azurelinuxagent.common.conf.get_provision_enabled',
        return_value=False)
    def test_provisioning_is_skipped_when_not_enabled(self, mock_conf):  # pylint: disable=unused-argument
        ph = ProvisionHandler()
        ph.osutil = DefaultOSUtil()
        ph.osutil.get_instance_id = Mock(
                        return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')

        ph.check_provisioned_file = Mock()
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        ph.run()

        self.assertEqual(0, ph.check_provisioned_file.call_count)
        self.assertEqual(1, ph.report_ready.call_count)
        self.assertEqual(1, ph.write_provisioned.call_count)

    @patch('os.path.isfile', return_value=False)
    def test_check_provisioned_file_not_provisioned(self, mock_isfile):  # pylint: disable=unused-argument
        ph = ProvisionHandler()
        self.assertFalse(ph.check_provisioned_file())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_check_provisioned_file_is_provisioned(self,
            mock_deprovision, mock_read, mock_isfile):  # pylint: disable=unused-argument

        ph = ProvisionHandler()
        ph.osutil = Mock()
        ph.osutil.is_current_instance_id = Mock(return_value=True)
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.check_provisioned_file())
        self.assertEqual(1, ph.osutil.is_current_instance_id.call_count)
        self.assertEqual(0, deprovision_handler.run_changed_unique_id.call_count)

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    @patch('azurelinuxagent.pa.deprovision.get_deprovision_handler')
    def test_check_provisioned_file_not_deprovisioned(self,
            mock_deprovision, mock_read, mock_isfile):  # pylint: disable=unused-argument

        ph = ProvisionHandler()
        ph.osutil = Mock()
        ph.osutil.is_current_instance_id = Mock(return_value=False)
        ph.report_ready = Mock()
        ph.write_provisioned = Mock()

        deprovision_handler = Mock()
        mock_deprovision.return_value = deprovision_handler

        self.assertTrue(ph.check_provisioned_file())
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
        self._provision_test(distro_name,  # pylint: disable=no-value-for-parameter
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
        self._provision_test(distro_name,  # pylint: disable=no-value-for-parameter
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
        self._provision_test(distro_name,  # pylint: disable=no-value-for-parameter
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
        self._provision_test(distro_name,  # pylint: disable=no-value-for-parameter
                             distro_version,
                             distro_full_name,
                             'ovf-env-4.xml',
                             'bad data',
                             True)

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_instance_id',
           return_value='B9F3C233-9913-9F42-8EB3-BA656DF32502')
    @patch('azurelinuxagent.pa.provision.default.ProvisionHandler.write_agent_disabled')
    @patch('azurelinuxagent.pa.provision.default.cloud_init_is_enabled', return_value=False)
    def _provision_test(self,
                        distro_name,
                        distro_version,
                        distro_full_name,
                        ovf_file,
                        provisionMessage,
                        expect_success,
                        # pylint:disable=unused-argument
                        patch_cloud_init_is_enabled,
                        patch_write_agent_disabled,
                        patch_get_instance_id):
        """
        Assert that the agent issues two telemetry messages as part of a
        successful provisioning.

         1. Provision
         2. GuestState
        """
        ph = get_provision_handler(distro_name,
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

            expected_disabled = True if provisionMessage == 'false' else False
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
    @patch('azurelinuxagent.pa.provision.default.cloud_init_is_enabled', return_value=False)
    def test_provision_telemetry_fail(self,
                                      distro_name,
                                      distro_version,
                                      distro_full_name,
                                      # pylint:disable=unused-argument
                                      patch_cloud_init_is_enabled,
                                      patch_get_provisioning_agent,
                                      mock_util):
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
        ph.protocol_util.get_protocol = MagicMock()

        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)

        ph.run()
        positional_args, kw_args = ph.report_event.call_args_list[0]  # pylint: disable=unused-variable
        self.assertTrue(re.match(r'Provisioning failed: \[ProvisionError\] --unit-test-- \(\d+\.\d+s\)', positional_args[0]) is not None)

    @distros()
    def test_handle_provision_guest_agent(self, distro_name, distro_version, distro_full_name):
        with patch('azurelinuxagent.pa.provision.default.ProvisionHandler.write_agent_disabled') as patch_write_agent_disabled:
            ph = get_provision_handler(distro_name, distro_version, distro_full_name)

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
            patch_cloud_init_is_enabled,  # pylint: disable=unused-argument
            patch_get_provisioning_agent):  # pylint: disable=unused-argument
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
            patch_cloud_init_is_enabled,  # pylint: disable=unused-argument
            patch_get_provisioning_agent):  # pylint: disable=unused-argument
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
            patch_cloud_init_is_enabled,  # pylint: disable=unused-argument
            patch_get_provisioning_agent):  # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, CloudInitProvisionHandler, 'Auto provisioning handler should be cloud-init if cloud-init is enabled')

    @patch(
        'azurelinuxagent.common.conf.get_provisioning_agent',
        return_value='cloud-init'
    )
    def test_get_provision_handler_config_cloudinit(
            self,
            patch_get_provisioning_agent):  # pylint: disable=unused-argument
        provisioning_handler = get_provision_handler()
        self.assertIsInstance(provisioning_handler, CloudInitProvisionHandler, 'Provisioning handler should be cloud-init if agent is set to cloud-init')


    @staticmethod
    @contextlib.contextmanager
    def _create_provision_handler_with_mock_protocol():
        handler = ProvisionHandler()
        handler.protocol_util = Mock()

        with mock_wire_protocol(wire_protocol_data.DATA_FILE, detect_protocol=False) as mock_protocol:
            handler.protocol_util.get_protocol = Mock(return_value=mock_protocol)
            yield handler, mock_protocol

    def test_it_should_not_download_certificates_when_the_public_key_has_a_value(self):
        ovfenv = OvfEnv(load_data("ovf-env_public_key.xml"))
        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, protocol):
            handler._download_ssh_keys_if_needed(ovfenv)
        self.assertEqual(0, protocol.mock_wire_data.call_counts['certificates'], "The Certificates package should not have been retrieved")

    def test_it_should_download_certificates_when_the_public_key_does_not_have_a_value(self):
        ovfenv = OvfEnv(load_data("ovf-env_public_key_no_value.xml"))
        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, protocol):
            handler._download_ssh_keys_if_needed(ovfenv)
        self.assertEqual(1, protocol.mock_wire_data.call_counts['certificates'], "The Certificates package should have been retrieved")
        ssh_key_path = os.path.join(conf.get_lib_dir(), '8979F1AC8C4215827BF3B5A403E6137B504D02A4.crt')
        self.assertTrue(os.path.exists(ssh_key_path), 'The SSH key was not downloaded. Expected: {0}'.format(ssh_key_path))

    def test_it_should_download_certificates_when_key_pairs_need_to_be_deployed(self):
        ovfenv = OvfEnv(load_data("ovf-env_key_pair.xml"))
        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, protocol):
            handler._download_ssh_keys_if_needed(ovfenv)
        self.assertEqual(1, protocol.mock_wire_data.call_counts['certificates'], "The Certificates package should have been retrieved")
        ssh_key_path = os.path.join(conf.get_lib_dir(), '8979F1AC8C4215827BF3B5A403E6137B504D02A4.crt')
        self.assertTrue(os.path.exists(ssh_key_path), 'The SSH key was not downloaded. Expected: {0}'.format(ssh_key_path))

    def test_it_should_retry_downloading_the_certificates(self):
        ovfenv = OvfEnv(load_data("ovf-env_public_key_no_value.xml"))

        def mock_http_get(url, *_, **__):
            if HttpRequestPredicates.is_certificates_request(url):
                mock_http_get.call_count += 1
                if mock_http_get.call_count <= 10:
                    return Exception("Mock failure")
            return None
        mock_http_get.call_count = 0

        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, protocol):
            protocol.set_http_handlers(http_get_handler=mock_http_get)
            with patch('azurelinuxagent.pa.provision.default.PROBE_INTERVAL', 0):  # set the delay between retries to 0
                handler._download_ssh_keys_if_needed(ovfenv)
        self.assertEqual(11, mock_http_get.call_count, "Expected 11 requests for Certificates (10 failed and retried requests, and 1 successful request)")
        ssh_key_path = os.path.join(conf.get_lib_dir(), '8979F1AC8C4215827BF3B5A403E6137B504D02A4.crt')
        self.assertTrue(os.path.exists(ssh_key_path), 'The SSH key was not downloaded. Expected: {0}'.format(ssh_key_path))

    def test_it_should_retry_downloading_the_certificates_the_maximum_number_of_retries(self):
        ovfenv = OvfEnv(load_data("ovf-env_public_key_no_value.xml"))

        def mock_http_get(url, *_, **__):
            if HttpRequestPredicates.is_certificates_request(url):
                mock_http_get.call_count += 1
                return Exception("Mock failure")
            return None
        mock_http_get.call_count = 0

        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, protocol):
            protocol.set_http_handlers(http_get_handler=mock_http_get)
            with patch('azurelinuxagent.pa.provision.default.PROBE_INTERVAL', 0):  # set the delay between retries to 0
                handler._download_ssh_keys_if_needed(ovfenv)
        self.assertEqual(2 * MAX_RETRY, mock_http_get.call_count, "Expected maximum number of retries ({0}) to have been attempted".format(MAX_RETRY))  # times 2 since two ciphers are attempted for FIPS support
        ssh_key_path = os.path.join(conf.get_lib_dir(), '8979F1AC8C4215827BF3B5A403E6137B504D02A4.crt')
        self.assertFalse(os.path.exists(ssh_key_path), 'The SSH key should not have been downloaded, since all requests failed. Got: {0}'.format(ssh_key_path))

    def test_deploy_ssh_pubkeys_should_raise_if_no_keys_have_been_downloaded(self):
        ovfenv_data = load_data("ovf-env_public_key_no_value.xml")
        ovfenv_data = ovfenv_data.replace('<UserName>UserName</UserName>', '<UserName>{0}</UserName>'.format(getpass.getuser()))
        ovfenv_data = ovfenv_data.replace('<Path>$HOME/UserName/.ssh/authorized_keys</Path>', '<Path>{0}</Path>'.format(os.path.join(self.tmp_dir, "authorized_keys")))
        ovfenv = OvfEnv(ovfenv_data)
        with TestProvision._create_provision_handler_with_mock_protocol() as (handler, _):
            with self.assertRaises(OSUtilError) as context:
                handler.deploy_ssh_pubkeys(ovfenv)
            self.assertIn("Can't find 8979F1AC8C4215827BF3B5A403E6137B504D02A4.crt", ustr(context.exception))


if __name__ == '__main__':
    unittest.main()

