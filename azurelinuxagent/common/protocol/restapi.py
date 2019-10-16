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


class VMInfo(DataContract):
    def __init__(self,
                 subscriptionId=None,
                 vmName=None,
                 containerId=None,
                 roleName=None,
                 roleInstanceName=None,
                 tenantName=None):
        self.subscriptionId = subscriptionId
        self.vmName = vmName
        self.containerId = containerId
        self.roleName = roleName
        self.roleInstanceName = roleInstanceName
        self.tenantName = tenantName


class CertificateData(DataContract):
    def __init__(self, certificateData=None):
        self.certificateData = certificateData


class Cert(DataContract):
    def __init__(self,
                 name=None,
                 thumbprint=None,
                 certificateDataUri=None,
                 storeName=None,
                 storeLocation=None):
        self.name = name
        self.thumbprint = thumbprint
        self.certificateDataUri = certificateDataUri
        self.storeLocation = storeLocation
        self.storeName = storeName


class CertList(DataContract):
    def __init__(self):
        self.certificates = DataContractList(Cert)


# TODO: confirm vmagent manifest schema
class VMAgentManifestUri(DataContract):
    def __init__(self, uri=None):
        self.uri = uri


class VMAgentManifest(DataContract):
    def __init__(self, family=None):
        self.family = family
        self.versionsManifestUris = DataContractList(VMAgentManifestUri)


class VMAgentManifestList(DataContract):
    def __init__(self):
        self.vmAgentManifests = DataContractList(VMAgentManifest)


class Extension(DataContract):
    def __init__(self,
                 name=None,
                 sequenceNumber=None,
                 publicSettings=None,
                 protectedSettings=None,
                 certificateThumbprint=None,
                 dependencyLevel=0):
        self.name = name
        self.sequenceNumber = sequenceNumber
        self.publicSettings = publicSettings
        self.protectedSettings = protectedSettings
        self.certificateThumbprint = certificateThumbprint
        self.dependencyLevel = dependencyLevel


class ExtHandlerProperties(DataContract):
    def __init__(self):
        self.version = None
        self.state = None
        self.extensions = DataContractList(Extension)


class ExtHandlerVersionUri(DataContract):
    def __init__(self):
        self.uri = None


class ExtHandler(DataContract):
    def __init__(self, name=None):
        self.name = name
        self.properties = ExtHandlerProperties()
        self.versionUris = DataContractList(ExtHandlerVersionUri)

    def sort_key(self):
        levels = [e.dependencyLevel for e in self.properties.extensions]
        if len(levels) == 0:
            level = 0
        else:
            level = min(levels)
        # Process uninstall or disabled before enabled, in reverse order
        # remap 0 to -1, 1 to -2, 2 to -3, etc
        if self.properties.state != u"enabled":
            level = (0 - level) - 1
        return level


class ExtHandlerList(DataContract):
    def __init__(self):
        self.extHandlers = DataContractList(ExtHandler)


class ExtHandlerPackageUri(DataContract):
    def __init__(self, uri=None):
        self.uri = uri


class ExtHandlerPackage(DataContract):
    def __init__(self, version=None):
        self.version = version
        self.uris = DataContractList(ExtHandlerPackageUri)
        # TODO update the naming to align with metadata protocol
        self.isinternal = False
        self.disallow_major_upgrade = False


class ExtHandlerPackageList(DataContract):
    def __init__(self):
        self.versions = DataContractList(ExtHandlerPackage)


class VMProperties(DataContract):
    def __init__(self, certificateThumbprint=None):
        # TODO need to confirm the property name
        self.certificateThumbprint = certificateThumbprint


class ProvisionStatus(DataContract):
    def __init__(self, status=None, subStatus=None, description=None):
        self.status = status
        self.subStatus = subStatus
        self.description = description
        self.properties = VMProperties()


class ExtensionSubStatus(DataContract):
    def __init__(self, name=None, status=None, code=None, message=None):
        self.name = name
        self.status = status
        self.code = code
        self.message = message


class ExtensionStatus(DataContract):
    def __init__(self,
                 configurationAppliedTime=None,
                 operation=None,
                 status=None,
                 seq_no=None,
                 code=None,
                 message=None):
        self.configurationAppliedTime = configurationAppliedTime
        self.operation = operation
        self.status = status
        self.sequenceNumber = seq_no
        self.code = code
        self.message = message
        self.substatusList = DataContractList(ExtensionSubStatus)


class ExtHandlerStatus(DataContract):
    def __init__(self,
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


class VMAgentStatus(DataContract):
    def __init__(self, status=None, message=None):
        self.status = status
        self.message = message
        self.hostname = socket.gethostname()
        self.version = str(CURRENT_VERSION)
        self.osname = DISTRO_NAME
        self.osversion = DISTRO_VERSION
        self.extensionHandlers = DataContractList(ExtHandlerStatus)


class VMStatus(DataContract):
    def __init__(self, status, message):
        self.vmAgent = VMAgentStatus(status=status, message=message)


class RemoteAccessUser(DataContract):
    def __init__(self, name, encrypted_password, expiration):
        self.name = name
        self.encrypted_password = encrypted_password
        self.expiration = expiration


class RemoteAccessUsersList(DataContract):
    def __init__(self):
        self.users = DataContractList(RemoteAccessUser)


class Protocol(DataContract):
    def detect(self):
        raise NotImplementedError()

    def get_vminfo(self):
        raise NotImplementedError()

    def get_certs(self):
        raise NotImplementedError()

    def get_incarnation(self):
        raise NotImplementedError()

    def get_vmagent_manifests(self):
        raise NotImplementedError()

    def get_vmagent_pkgs(self, manifest):
        raise NotImplementedError()

    def get_ext_handlers(self):
        raise NotImplementedError()

    def get_ext_handler_pkgs(self, extension):
        raise NotImplementedError()

    def get_artifacts_profile(self):
        raise NotImplementedError()

    def download_ext_handler_pkg(self, uri, destination, headers=None, use_proxy=True):
        raise NotImplementedError()

    def report_provision_status(self, provision_status):
        raise NotImplementedError()

    def report_vm_status(self, vm_status):
        raise NotImplementedError()

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        raise NotImplementedError()

    def report_event(self, event):
        raise NotImplementedError()

    def supports_overprovisioning(self):
        return True
