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
from azurelinuxagent.common import event
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.exception import HttpError


# Minimum IMDS version that supports the "securityProfile.securityType" attribute.
MIN_IMDS_VERSION_WITH_SECURITY_TYPE = '2021-12-13'


class SecurityType(object):
    # These values correspond to the 'securityProfile.securityType' field
    # in the Microsoft.Compute/virtualMachines ARM template schema.
    # See: https://learn.microsoft.com/azure/templates/microsoft.compute/virtualmachines#securityprofile
    TrustedVM = "TrustedLaunch"
    ConfidentialVM = "ConfidentialVM"


class ConfidentialVMInfo(object):
    # This class temporarily provides a way to detect whether the VM is a Confidential VM (CVM) via IMDS.
    # It is used to limit certain features to CVMs while we build confidence in the feature
    # before enabling it across the broader fleet (telemetry/preview releases only).
    #
    # TODO: Remove once extension signature validation is supported on all VMs.

    _security_type = None

    @staticmethod
    def _get_security_type_from_imds():
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
            raise ValueError("missing field 'securityProfile'")

        return security_type

    @staticmethod
    def is_confidential_vm():
        # Get and cache the VM's security type from IMDS if not already done
        if ConfidentialVMInfo._security_type is None:
            try:
                security_type = ConfidentialVMInfo._get_security_type_from_imds()
                event.info("VM security type: {0}", security_type)
                ConfidentialVMInfo._security_type = security_type
            except Exception as ex:
                event.warn("Failed to get virtual machine security type from IMDS: {0}", ustr(ex))

        return ConfidentialVMInfo._security_type == SecurityType.ConfidentialVM
