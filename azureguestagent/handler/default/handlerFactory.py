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

from azureguestagent.handler.default.scvmmHandler import ScvmmHandler
from azureguestagent.handler.default.dhcpHandler import DhcpHandler
from azureguestagent.handler.default.envHandler import EnvHandler
from azureguestagent.handler.default.provisionHandler import ProvisionHandler
from azureguestagent.handler.default.resourceDiskHandler import ResourceDiskHandler
from azureguestagent.handler.default.extensionHandler import ExtensionHandler
from azureguestagent.handler.default.deprovisionHandler import DeprovisionHandler

class DefaultHandlerFactory(object):

    def getScvmmHandler(self):
        return ScvmmHandler()

    def getEnvHandler(self):
        return EnvHandler()

    def getDhcpHandler(self):
        return DhcpHandler()

    def getProvisionHandler(self):
        return ProvisionHandler()

    def getResourceDiskHandler(self):
        return ResourceDiskHandler()

    def getExtensionHandler(self):
        return ExtensionHandler()

    def getDeprovionHandler(self):
        return DeprovisionHandler()
