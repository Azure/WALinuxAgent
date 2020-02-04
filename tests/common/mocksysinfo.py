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

from azurelinuxagent.common.telemetryevent import TelemetryEventParam


class SysInfoData(object):

    @staticmethod
    def get_sysinfo_telemetry_params():
        final_telemetry_params = [
            TelemetryEventParam("OSVersion", "TEST_OSVersion"),
            TelemetryEventParam("ExecutionMode", "TEST_ExecutionMode"),
            TelemetryEventParam("RAM", 512),
            TelemetryEventParam("Processors", 2),
            TelemetryEventParam("VMName", "TEST_VMName"),
            TelemetryEventParam("TenantName", "TEST_TenantName"),
            TelemetryEventParam("RoleName", "TEST_RoleName"),
            TelemetryEventParam("RoleInstanceName", "TEST_RoleInstanceName"),
            TelemetryEventParam("Location", "TEST_Location"),
            TelemetryEventParam("SubscriptionId", "TEST_SubscriptionId"),
            TelemetryEventParam("ResourceGroupName", "TEST_ResourceGroupName"),
            TelemetryEventParam("VMId", "TEST_VMId"),
            TelemetryEventParam("ImageOrigin", 1),
        ]
        return final_telemetry_params
