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

import json

from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo
from tests.lib.tools import AgentTestCase, MagicMock, patch


class TestConfidentialVMInfo(AgentTestCase):

    def setUp(self):
        ConfidentialVMInfo._security_type = None
        AgentTestCase.setUp(self)

    def _get_mock_imds_response(self, security_type, success=True):
        mock_response = MagicMock()
        if success:
            mock_metadata = {
                "azEnvironment": "AZUREPUBLICCLOUD",
                "additionalCapabilities": {},
                "hostGroup": {},
                "extendedLocation": {},
                "evictionPolicy": "",
                "isHostCompatibilityLayerVm": "true",
                "licenseType": "",
                "location": "westus",
                "name": "examplevmname",
                "offer": "UbuntuServer",
                "osProfile": {},
                "osType": "Linux",
                "placementGroupId": "f67c14ab-e92c-408c-ae2d-da15866ec79a",
                "plan": {},
                "platformFaultDomain": "36",
                "platformSubFaultDomain": "",
                "platformUpdateDomain": "42",
                "priority": "Regular",
                "publicKeys": [],
                "publisher": "Canonical",
                "resourceGroupName": "macikgo-test-may-23",
                "resourceId": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/virtualMachines/examplevmname",
                "securityProfile": {
                    "secureBootEnabled": "true",
                    "virtualTpmEnabled": "false",
                    "encryptionAtHost": "true",
                    "securityType": security_type
                },
                "sku": "18.04-LTS",
                "storageProfile": {},
                "subscriptionId": "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx",
                "tags": "baz:bash;foo:bar",
                "version": "15.05.22",
                "virtualMachineScaleSet": {
                    "id": "/subscriptions/xxxxxxxx-xxxxx-xxx-xxx-xxxx/resourceGroups/resource-group-name/providers/Microsoft.Compute/virtualMachineScaleSets/virtual-machine-scale-set-name"
                },
                "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",
                "vmScaleSetName": "crpteste9vflji9",
                "vmSize": "Standard_A3",
                "zone": ""
            }
        else:
            mock_metadata = "Unable to connect to endpoint"

        mock_response.success = success
        mock_response.response = json.dumps(mock_metadata).encode("utf-8")
        return mock_response

    def test_should_identify_confidential_vm(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            mock_response = self._get_mock_imds_response(security_type="ConfidentialVM")
            mock_get_metadata.return_value = mock_response

            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertTrue(is_cvm)

    def test_should_identify_non_confidential_vm(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            mock_response = self._get_mock_imds_response(security_type="TrustedLaunch")
            mock_get_metadata.return_value = mock_response

            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(is_cvm)

    def test_should_handle_imds_failure(self):
        with patch('azurelinuxagent.ga.confidential_vm_info.ImdsClient.get_metadata') as mock_get_metadata:
            mock_response = self._get_mock_imds_response("ConfidentialVM", success=False)
            mock_get_metadata.return_value = mock_response

            is_cvm = ConfidentialVMInfo.is_confidential_vm()
            self.assertFalse(is_cvm)
