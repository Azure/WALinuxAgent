# Windows Azure Linux Agent
#
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

import json

from azurelinuxagent.common.protocol.imds import ImdsClient
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.exception import HttpError


# Minimum IMDS version that supports the "securityProfile.securityType" attribute.
MIN_IMDS_VERSION_WITH_SECURITY_TYPE = '2021-12-13'


class SecurityType(object):
    # Corresponds to the 'securityProfile.securityType' field
    # in the Microsoft.Compute/virtualMachines ARM template schema.
    # See: https://learn.microsoft.com/azure/templates/microsoft.compute/virtualmachines#securityprofile
    ConfidentialVM = "ConfidentialVM"


class ConfidentialVMInfo(object):
    # This class temporarily provides a way to detect whether the VM is a Confidential VM (CVM) via IMDS.
    # It is used to limit certain features to CVMs while we build confidence in the feature
    # before enabling it across the broader fleet (telemetry/preview releases only).
    #
    # TODO: Remove once extension signature validation is supported on all VMs.

    # Tri-state boolean:
    # - True if CVM
    # - False if not a CVM or unable to determine security type (e.g., IMDS call fails)
    # - None if not yet initialized (fetch_and_initialize_cvm_info has not been called)
    _is_confidential_vm = None

    @staticmethod
    def _fetch_security_type_from_imds():
        imds_client = ImdsClient(MIN_IMDS_VERSION_WITH_SECURITY_TYPE)
        result = imds_client.get_metadata('instance/compute', is_health=False)
        if not result.success:
            raise HttpError(result.response)

        # Get securityProfile attribute
        compute_json = json.loads(ustr(result.response, encoding="utf-8"))
        security_profile = compute_json.get('securityProfile')
        if security_profile is None:
            raise ValueError("missing field 'securityProfile'")

        # Get securityType attribute
        security_type = security_profile.get('securityType')
        if security_type is None:
            raise ValueError("missing field 'securityType'")

        return security_type

    @staticmethod
    def fetch_and_initialize_cvm_info():
        """
        Fetches the security type from IMDS and initializes the CVM state.
        Note: This is called before telemetry parameters are initialized, so telemetry should be sent by the caller.
        """
        try:
            security_type = ConfidentialVMInfo._fetch_security_type_from_imds()
            ConfidentialVMInfo._is_confidential_vm = (security_type == SecurityType.ConfidentialVM)
        except Exception as ex:
            # TODO: For now, in the case of IMDS failure, we treat the VM as non-CVM until the next agent service start.
            # This should be improved to better distinguish IMDS issues from true security type.
            ConfidentialVMInfo._is_confidential_vm = False
            raise ex

    @staticmethod
    def is_confidential_vm():
        if ConfidentialVMInfo._is_confidential_vm is None:
            raise RuntimeError("Confidential VM Information is not initialized.")
        return ConfidentialVMInfo._is_confidential_vm
