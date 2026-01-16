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
# Requires Python 2.4+ and Openssl 1.0+
#

import os

from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo
from tests.lib.tools import AgentTestCase, MagicMock, patch, data_dir


@patch('azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo._is_confidential_vm', None)
class TestConfidentialVMInfo(AgentTestCase):

    @staticmethod
    def _setup_mock_imds_from_file(mock_get_metadata, file_path):
        with open(file_path, "r") as f:
            metadata_json = f.read()
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.response = metadata_json.encode("utf-8")
        mock_get_metadata.return_value = mock_response

    def test_should_identify_confidential_vm(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            self._setup_mock_imds_from_file(mock_get_metadata, os.path.join(data_dir, "imds", "cvm_metadata.json"))
            ConfidentialVMInfo.fetch_and_initialize_cvm_info()
            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertTrue(is_cvm)

    def test_should_identify_non_confidential_vm(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            self._setup_mock_imds_from_file(mock_get_metadata, os.path.join(data_dir, "imds", "trusted_vm_metadata.json"))
            ConfidentialVMInfo.fetch_and_initialize_cvm_info()
            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(is_cvm)

    def test_should_return_false_when_imds_unavailable(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            # Mock an IMDS failure response
            mock_response = MagicMock()
            mock_response.success = False
            mock_response.response = b"Unable to connect to IMDS"
            mock_get_metadata.return_value = mock_response

            # The method should raise an exception when IMDS is unavailable
            with self.assertRaises(Exception):
                ConfidentialVMInfo.fetch_and_initialize_cvm_info()
            # After exception, is_confidential_vm should be False
            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(is_cvm)

    def test_should_always_return_false_after_transient_imds_failure(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            # Mock a transient IMDS failure - error on first call, success on second call
            failure_response = MagicMock()
            failure_response.success = False
            failure_response.response = b"Network timeout"
            success_response = MagicMock()
            success_response.success = True
            success_response.response = b'{"securityProfile": {"securityType": "ConfidentialVM"}}'
            mock_get_metadata.side_effect = [failure_response, success_response]

            # First call should raise an exception due to failure
            with self.assertRaises(Exception):
                ConfidentialVMInfo.fetch_and_initialize_cvm_info()
            first_call = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(first_call)
            second_call = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(second_call)

            # Verify IMDS was only called once
            self.assertEqual(mock_get_metadata.call_count, 1)

    def test_should_raise_error_when_cvm_info_uninitialized(self):
        # Reset to uninitialized state
        ConfidentialVMInfo._is_confidential_vm = None

        # Calling is_confidential_vm() before initialization should raise RuntimeError
        with self.assertRaises(RuntimeError) as context:
            ConfidentialVMInfo.is_confidential_vm()
            self.assertIn("not initialized", str(context.exception))
