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
from threading import Lock
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.telemetryevent import TelemetryEventParam
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, AGENT_EXECUTION_MODE


class SysInfo(object):

    _instance = None
    _lock = Lock()

    @staticmethod
    def get_instance():
        with SysInfo._lock:
            if SysInfo._instance is None:
                SysInfo._instance = SysInfo().__impl()
            return SysInfo._instance

    class __impl(object):
        def __init__(self):
            self._vminfo = None
            self._compute_info = None
            self._osutil = get_osutil()
            self._telemetry_params = []

        def _set_vminfo(self, vminfo, compute_info):
            # This method should only be called once, on service startup, from update.py. It will retrieve and populate
            # the necessary sysinfo fields into this object, which will be later used for reporting telemetry.
            self._vminfo = vminfo
            self._compute_info = compute_info
            self._init_sysinfo_params()
            self._build_sysinfo_telemetry_params()

        def get_sysinfo_telemetry_params(self):
            return self._telemetry_params

        def _init_sysinfo_params(self):
            # Build a dictionary of null values to ensure the schema is consistent even if we fail to retrieve some
            # of these values.
            params_names = ["OSVersion", "ExecutionMode", "RAM", "Processors", "VMName", "TenantName", "RoleName",
                            "RoleInstanceName", "Location", "SubscriptionId", "ResourceGroupName", "VMId",
                            "ImageOrigin"]

            self.params_dict = {}
            for key in params_names:
                self.params_dict[key] = None

            osversion = "{0}:{1}-{2}-{3}:{4}".format(platform.system(),
                                                     DISTRO_NAME,
                                                     DISTRO_VERSION,
                                                     DISTRO_CODE_NAME,
                                                     platform.release())
            self.params_dict["OSVersion"] = osversion
            self.params_dict["ExecutionMode"] = AGENT_EXECUTION_MODE

            try:
                ram = self._osutil.get_total_mem()
                processors = self._osutil.get_processor_cores()
                self.params_dict["RAM"] = int(ram)
                self.params_dict["Processors"] = int(processors)
            except OSUtilError as e:
                logger.warn("Failed to get system info: {0}", ustr(e))

            self.params_dict["VMName"] = self._vminfo.vmName
            self.params_dict["TenantName"] = self._vminfo.tenantName
            self.params_dict["RoleName"] = self._vminfo.roleName
            self.params_dict["RoleInstanceName"] = self._vminfo.roleInstanceName

            self.params_dict["Location"] = self._compute_info.location
            self.params_dict["SubscriptionId"] = self._compute_info.subscriptionId
            self.params_dict["ResourceGroupName"] = self._compute_info.resourceGroupName
            self.params_dict["VMId"] = self._compute_info.vmId
            self.params_dict["ImageOrigin"] = int(self._compute_info.image_origin)

        def _build_sysinfo_telemetry_params(self):
            self._telemetry_params = []
            for param_name in self.params_dict:
                self._telemetry_params.append(TelemetryEventParam(param_name, self.params_dict[param_name]))
