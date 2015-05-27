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

import azureguestagent.utils.restutil as restutil
from azureguestagent.protocol.common import *

class VmInfoV2(object):
    def __init__(self, data):
        self.data = data

    def getSubscriptionId(self):
        return self.data["subscriptionId"]

    def getVmName(self):
        return self.data["vmName"]

class CertInfoV2(object):
    def __init__(self, data):
        self.data = data

    def getName(self):
        return self.data["name"]

    def getThumbprint(self):
        return self.data["thumbprint"]

    def getCrtFile(self):
        return self.data["crt"]

    def getPrvFile(self):
        return self.data["prv"]


class ExtensionInfoV2(ExtensionInfo):
    def __init__(self, data):
        self.data = data

    def getName(self):
        return self.data["name"]

    def getVersion(self):
        return self.data["properties"]["version"]

    def setVersion(self, version):
        self.data["properties"]["version"] = version

    def getVersionUris(self):
        #TODO download version json
        return self.data["properties"]["versionUris"]

    def getUpgradePolicy(self):
        return self.data["properties"]["upgrade-policy"]

    def getState(self):
        return self.data["properties"]["state"]

    def getSeqNo(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["sequenceNumber"]

    def getPublicSettings(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["publicSettings"]

    def getProtectedSettings(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["privateSettings"]

    def getCertificateThumbprint(self):
        settings = self.data["properties"]["runtimeSettings"][0]
        return settings["handlerSettings"]["certificateThumbprint"]

class ProtocolV2(Protocol):

    __MetadataServerAddr='169.254.169.254'
    __ApiVersion='2015-01-01'
    __IdentityService=("https://{0}/identity?$get-children=true&"
                       "api-version={{{1}}}").format(__MetadataServerAddr, 
                                                  __ApiVersion)

    def __init__(self):
        raise NotImplementedError()

    def getVmInfo(self):
        raise NotImplementedError()

    def getCerts(self):
        raise NotImplementedError()

    def getExtensions(self):
        raise NotImplementedError()

    def getOvf(self):
        raise NotImplementedError()

    def reportProvisionStatus(self, status, subStatus, description, thumbprint):
        raise NotImplementedError()

    def reportAgentStatus(self, version, status, message):
        raise NotImplementedError()

    def reportExtensionStatus(self, name, version, statusJson):
        raise NotImplementedError()
    
    def reportEvent(self):
        raise NotImplementedError()

