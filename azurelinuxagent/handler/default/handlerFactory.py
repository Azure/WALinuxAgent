# Windows Azure Linux Agent
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

from azurelinuxagent.handler.default.scvmmHandler import ScvmmHandler
from azurelinuxagent.handler.default.dhcpHandler import DhcpHandler
from azurelinuxagent.handler.default.envHandler import EnvHandler
from azurelinuxagent.handler.default.provisionHandler import ProvisionHandler
from azurelinuxagent.handler.default.resourceDiskHandler import ResourceDiskHandler
from azurelinuxagent.handler.default.extensionHandler import ExtensionHandler
from azurelinuxagent.handler.default.deprovisionHandler import DeprovisionHandler

class DefaultHandlerFactory(object):
    def __init__(self):
        self.scvmmHandler = ScvmmHandler()
        self.dhcpHandler = DhcpHandler()
        self.envHandler = EnvHandler(self.dhcpHandler)
        self.provisionHandler = ProvisionHandler()
        self.resourceDiskHandler = ResourceDiskHandler()
        self.extensionHandler = ExtensionHandler()
        self.deprovisionHandler = DeprovisionHandler()

    def getScvmmHandler(self):
        return self.scvmmHandler

    def getEnvHandler(self):
        return self.envHandler

    def getDhcpHandler(self):
        return self.dhcpHandler

    def getProvisionHandler(self):
        return self.provisionHandler

    def getResourceDiskHandler(self):
        return self.resourceDiskHandler

    def getExtensionHandler(self):
        return self.extensionHandler

    def getDeprovionHandler(self):
        return self.deprovisionHandler

