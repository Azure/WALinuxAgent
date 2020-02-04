# Copyright 2020 Microsoft Corporation
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

import platform

from azurelinuxagent.common.protocol.imds import ComputeInfo
from azurelinuxagent.common.protocol.restapi import VMInfo
from azurelinuxagent.common.sysinfo import SysInfo
from azurelinuxagent.common.version import AGENT_EXECUTION_MODE, DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME
from tests.tools import patch, AgentTestCase, PropertyMock


class TestSysInfo(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        SysInfo._instance = None

    @staticmethod
    def build_vminfo():
        vminfo = VMInfo()
        vminfo.vmName = "TEST_VMName"
        vminfo.tenantName = "TEST_TenantName"
        vminfo.roleName = "TEST_RoleName"
        vminfo.roleInstanceName = "Test_RoleInstanceName"

        compute_info = ComputeInfo()
        compute_info.location = "TEST_Location"
        compute_info.subscriptionId = "TEST_SubscriptionId"
        compute_info.resourceGroupName = "TEST_ResourceGroupName"
        compute_info.vmId = "TEST_VMId"

        return vminfo, compute_info

    @patch("azurelinuxagent.common.protocol.imds.ComputeInfo.image_origin", new_callable=PropertyMock(return_value=1))
    @patch("platform.release", return_value="platform-release")
    @patch("platform.system", return_value="Linux")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores", return_value=4)
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_mem", return_value=10000)
    def test_set_vm_info_should_populate_all_sysinfo_params(self, *args):
        sysinfo = SysInfo.get_instance()
        vminfo, compute_info = self.build_vminfo()

        expected_telemetry_params = {
            "OSVersion": "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                      DISTRO_NAME,
                                                      DISTRO_VERSION,
                                                      DISTRO_CODE_NAME,
                                                      platform.release()),
            "ExecutionMode": AGENT_EXECUTION_MODE,
            "RAM": 10000,
            "Processors": 4,
            "VMName": vminfo.vmName,
            "TenantName": vminfo.tenantName,
            "RoleName": vminfo.roleName,
            "RoleInstanceName": vminfo.roleInstanceName,
            "Location": compute_info.location,
            "SubscriptionId": compute_info.subscriptionId,
            "ResourceGroupName": compute_info.resourceGroupName,
            "VMId": compute_info.vmId,
            "ImageOrigin": compute_info.image_origin
        }

        sysinfo.set_vminfo(vminfo, compute_info)
        sysinfo_telemetry_params = sysinfo.get_sysinfo_telemetry_params()

        for sysinfo_telemetry_param in sysinfo_telemetry_params:
            expected_value = expected_telemetry_params[sysinfo_telemetry_param.name]
            actual_value = sysinfo_telemetry_param.value

            self.assertEquals(expected_value, actual_value)
