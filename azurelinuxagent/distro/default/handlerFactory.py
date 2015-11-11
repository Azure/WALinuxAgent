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
from .init import InitHandler
from .run import MainHandler
from .scvmm import ScvmmHandler
from .dhcp import DhcpHandler
from .env import EnvHandler
from .provision import ProvisionHandler
from .resourceDisk import ResourceDiskHandler
from .extension import ExtHandlersHandler
from .deprovision import DeprovisionHandler

class DefaultHandlerFactory(object):
    def __init__(self):
        self.init_handler = InitHandler()
        self.main_handler = MainHandler(self)
        self.scvmm_handler = ScvmmHandler()
        self.dhcp_handler = DhcpHandler()
        self.env_handler = EnvHandler(self)
        self.provision_handler = ProvisionHandler()
        self.resource_disk_handler = ResourceDiskHandler()
        self.ext_handlers_handler = ExtHandlersHandler()
        self.deprovision_handler = DeprovisionHandler()

