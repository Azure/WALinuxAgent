# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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

from azurelinuxagent.conf import ConfigurationProvider
from azurelinuxagent.distro.default.osutil import DefaultOSUtil
from azurelinuxagent.distro.default.daemon import DaemonHandler
from azurelinuxagent.distro.default.init import InitHandler
from azurelinuxagent.distro.default.monitor import MonitorHandler
from azurelinuxagent.distro.default.dhcp import DhcpHandler
from azurelinuxagent.distro.default.protocolUtil import ProtocolUtil
from azurelinuxagent.distro.default.scvmm import ScvmmHandler
from azurelinuxagent.distro.default.env import EnvHandler
from azurelinuxagent.distro.default.provision import ProvisionHandler
from azurelinuxagent.distro.default.resourceDisk import ResourceDiskHandler
from azurelinuxagent.distro.default.extension import ExtHandlersHandler
from azurelinuxagent.distro.default.deprovision import DeprovisionHandler

class DefaultDistro(object):
    """
    """
    def __init__(self):
        self.osutil = DefaultOSUtil()
        self.protocol_util = ProtocolUtil(self)

        self.init_handler = InitHandler(self)
        self.daemon_handler = DaemonHandler(self)
        self.event_handler = MonitorHandler(self)
        self.dhcp_handler = DhcpHandler(self)
        self.scvmm_handler = ScvmmHandler(self)
        self.env_handler = EnvHandler(self)
        self.provision_handler = ProvisionHandler(self)
        self.resource_disk_handler = ResourceDiskHandler(self)
        self.ext_handlers_handler = ExtHandlersHandler(self)
        self.deprovision_handler = DeprovisionHandler(self)

