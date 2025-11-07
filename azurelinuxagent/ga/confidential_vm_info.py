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

from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.future import ustr


class SecurityType(object):
    # The 'securityType' field comes from the VM's securityProfile section in Azure IMDS metadata.
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
    def is_confidential_vm():
        # Get and cache the VM's security type from IMDS if not already done
        if ConfidentialVMInfo._security_type is None:
            try:
                compute_info = get_imds_client().get_compute()
                security_type = compute_info.securityProfile.get('securityType')
                event.info("VM security type: {0}".format(security_type))
                ConfidentialVMInfo._security_type = security_type
            except Exception as ex:
                event.warn("Failed to get virtual machine security type from IMDS: {0}", ustr(ex))

        return ConfidentialVMInfo._security_type == SecurityType.ConfidentialVM
