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
import os
import copy
import re
import xml.dom.minidom
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.textutil import GetNodeTextData
import azurelinuxagent.utils.fileutil as fileutil

class VmInfo(object):
    def getSubscriptionId(self):
        raise NotImplementedError()

    def getVmName(self):
        raise NotImplementedError()

class CertInfo(object):
    def getName(self):
        raise NotImplementedError()

    def getThumbprint(self):
        raise NotImplementedError()

    def getCrtFile(self, thumbprint):
        raise NotImplementedError()

    def getPrvFile(self, thumbprint):
        raise NotImplementedError()

class ExtensionInfo(object):
    
    def getName(self):
        raise NotImplementedError()

    def getVersion(self):
        raise NotImplementedError()

    def getVersionUris(self):
        raise NotImplementedError()

    def getUpgradePolicy(self):
        raise NotImplementedError()

    def getState(self):
        raise NotImplementedError()

    def getSeqNo(self):
        raise NotImplementedError()

    def getSettings(self):
        raise NotImplementedError()
    
    def getHandlerSettings(self):
        raise NotImplementedError()
    
    def getPublicSettings(self):
        raise NotImplementedError()

    def getProtectedSettings(self):
        raise NotImplementedError()

    def getCertificateThumbprint(self):
        raise NotImplementedError()

class InstanceMetadata(object):
    def getDeploymentName(self):
        raise NotImplementedError()
        
    def getRoleName(self):
        raise NotImplementedError()
        
    def getRoleInstanceId(self):
        raise NotImplementedError()
        
    def getContainerId(self):
        raise NotImplementedError()

class ProtocolError(Exception):
    pass

class ProtocolNotFound(Exception):
    pass

class Protocol(object):
    def initialize(self):
        raise NotImplementedError()

    def getVmInfo(self):
        raise NotImplementedError()

    def getCerts(self):
        raise NotImplementedError()

    def getExtensions(self):
        raise NotImplementedError()
    
    def getExtensionVersions(self, name):
        raise NotImplementedError()

    def getInstanceMetadata(self):
        raise NotImplementedError()


    def reportProvisionStatus(self, status, subStatus, description, thumbprint):
        raise NotImplementedError()

    def reportAgentStatus(self, version, status, message):
        raise NotImplementedError()

    def reportExtensionStatus(self, name, version, statusJson):
        raise NotImplementedError()

    def reportEvent(self):
        raise NotImplementedError()

