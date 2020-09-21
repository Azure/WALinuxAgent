# Microsoft Azure Linux Agent
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

import socket
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME, CURRENT_VERSION
from azurelinuxagent.common.datacontract import DataContract, DataContractList


class VMInfo(DataContract): # pylint: disable=R0903
    def __init__(self, # pylint: disable=R0913
                 subscriptionId=None,
                 vmName=None,
                 roleName=None,
                 roleInstanceName=None,
                 tenantName=None):
        self.subscriptionId = subscriptionId # pylint: disable=C0103
        self.vmName = vmName # pylint: disable=C0103
        self.roleName = roleName # pylint: disable=C0103
        self.roleInstanceName = roleInstanceName # pylint: disable=C0103
        self.tenantName = tenantName # pylint: disable=C0103


class CertificateData(DataContract): # pylint: disable=R0903
    def __init__(self, certificateData=None):
        self.certificateData = certificateData # pylint: disable=C0103


class Cert(DataContract): # pylint: disable=R0903
    def __init__(self, # pylint: disable=R0913
                 name=None,
                 thumbprint=None,
                 certificateDataUri=None,
                 storeName=None,
                 storeLocation=None):
        self.name = name
        self.thumbprint = thumbprint
        self.certificateDataUri = certificateDataUri # pylint: disable=C0103
        self.storeLocation = storeLocation # pylint: disable=C0103
        self.storeName = storeName # pylint: disable=C0103


class CertList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.certificates = DataContractList(Cert)


# TODO: confirm vmagent manifest schema # pylint: disable=W0511
class VMAgentManifestUri(DataContract): # pylint: disable=R0903
    def __init__(self, uri=None):
        self.uri = uri


class VMAgentManifest(DataContract): # pylint: disable=R0903
    def __init__(self, family=None):
        self.family = family
        self.versionsManifestUris = DataContractList(VMAgentManifestUri) # pylint: disable=C0103


class VMAgentManifestList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.vmAgentManifests = DataContractList(VMAgentManifest) # pylint: disable=C0103


class Extension(DataContract): # pylint: disable=R0903
    def __init__(self, # pylint: disable=R0913
                 name=None,
                 sequenceNumber=None,
                 publicSettings=None,
                 protectedSettings=None,
                 certificateThumbprint=None,
                 dependencyLevel=0):
        self.name = name
        self.sequenceNumber = sequenceNumber # pylint: disable=C0103
        self.publicSettings = publicSettings # pylint: disable=C0103
        self.protectedSettings = protectedSettings # pylint: disable=C0103
        self.certificateThumbprint = certificateThumbprint # pylint: disable=C0103
        self.dependencyLevel = dependencyLevel # pylint: disable=C0103


class ExtHandlerProperties(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.version = None
        self.state = None
        self.extensions = DataContractList(Extension)


class ExtHandlerVersionUri(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.uri = None


class ExtHandler(DataContract): # pylint: disable=R0903
    def __init__(self, name=None):
        self.name = name
        self.properties = ExtHandlerProperties()
        self.versionUris = DataContractList(ExtHandlerVersionUri) # pylint: disable=C0103

    def sort_key(self):
        levels = [e.dependencyLevel for e in self.properties.extensions]
        if len(levels) == 0: # pylint: disable=len-as-condition
            level = 0
        else:
            level = min(levels)
        # Process uninstall or disabled before enabled, in reverse order
        # remap 0 to -1, 1 to -2, 2 to -3, etc
        if self.properties.state != u"enabled":
            level = (0 - level) - 1
        return level


class ExtHandlerList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.extHandlers = DataContractList(ExtHandler) # pylint: disable=C0103


class ExtHandlerPackageUri(DataContract): # pylint: disable=R0903
    def __init__(self, uri=None):
        self.uri = uri


class ExtHandlerPackage(DataContract): # pylint: disable=R0903
    def __init__(self, version=None):
        self.version = version
        self.uris = DataContractList(ExtHandlerPackageUri)
        # TODO update the naming to align with metadata protocol # pylint: disable=W0511
        self.isinternal = False
        self.disallow_major_upgrade = False


class ExtHandlerPackageList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.versions = DataContractList(ExtHandlerPackage)


class VMProperties(DataContract): # pylint: disable=R0903
    def __init__(self, certificateThumbprint=None):
        # TODO need to confirm the property name # pylint: disable=W0511
        self.certificateThumbprint = certificateThumbprint # pylint: disable=C0103


class ProvisionStatus(DataContract): # pylint: disable=R0903
    def __init__(self, status=None, subStatus=None, description=None):
        self.status = status
        self.subStatus = subStatus # pylint: disable=C0103
        self.description = description
        self.properties = VMProperties()


class ExtensionSubStatus(DataContract): # pylint: disable=R0903
    def __init__(self, name=None, status=None, code=None, message=None):
        self.name = name
        self.status = status
        self.code = code
        self.message = message


class ExtensionStatus(DataContract): # pylint: disable=R0903
    def __init__(self, # pylint: disable=R0913
                 configurationAppliedTime=None,
                 operation=None,
                 status=None,
                 seq_no=None,
                 code=None,
                 message=None):
        self.configurationAppliedTime = configurationAppliedTime # pylint: disable=C0103
        self.operation = operation
        self.status = status
        self.sequenceNumber = seq_no # pylint: disable=C0103
        self.code = code
        self.message = message
        self.substatusList = DataContractList(ExtensionSubStatus) # pylint: disable=C0103


class ExtHandlerStatus(DataContract): # pylint: disable=R0903
    def __init__(self, # pylint: disable=R0913
                 name=None,
                 version=None,
                 status=None,
                 code=0,
                 message=None):
        self.name = name
        self.version = version
        self.status = status
        self.code = code
        self.message = message
        self.extensions = DataContractList(ustr)


class VMAgentStatus(DataContract): # pylint: disable=R0903
    def __init__(self, status=None, message=None):
        self.status = status
        self.message = message
        self.hostname = socket.gethostname()
        self.version = str(CURRENT_VERSION)
        self.osname = DISTRO_NAME
        self.osversion = DISTRO_VERSION
        self.extensionHandlers = DataContractList(ExtHandlerStatus) # pylint: disable=C0103


class VMStatus(DataContract): # pylint: disable=R0903
    def __init__(self, status, message):
        self.vmAgent = VMAgentStatus(status=status, message=message) # pylint: disable=C0103


class RemoteAccessUser(DataContract): # pylint: disable=R0903
    def __init__(self, name, encrypted_password, expiration):
        self.name = name
        self.encrypted_password = encrypted_password
        self.expiration = expiration


class RemoteAccessUsersList(DataContract): # pylint: disable=R0903
    def __init__(self):
        self.users = DataContractList(RemoteAccessUser)

