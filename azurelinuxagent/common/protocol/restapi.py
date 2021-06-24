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
from datetime import datetime, timedelta

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.textutil import getattrib
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME, CURRENT_VERSION
from azurelinuxagent.common.datacontract import DataContract, DataContractList


class VMInfo(DataContract):
    def __init__(self,
                 subscriptionId=None,
                 vmName=None,
                 roleName=None,
                 roleInstanceName=None,
                 tenantName=None):
        self.subscriptionId = subscriptionId
        self.vmName = vmName
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
    """
    The runtime settings associated with a Handler
    -   Maps to Extension.PluginSettings.Plugin.RuntimeSettings for single config extensions in the ExtensionConfig.xml
        Eg: 1.settings, 2.settings
    -   Maps to Extension.PluginSettings.Plugin.ExtensionRuntimeSettings for multi-config extensions in the
        ExtensionConfig.xml
        Eg: <extensionName>.1.settings, <extensionName>.2.settings
    """

    def __init__(self,
                 name=None,
                 sequenceNumber=None,
                 publicSettings=None,
                 protectedSettings=None,
                 certificateThumbprint=None,
                 dependencyLevel=0,
                 state="enabled"):
        self.name = name
        self.sequenceNumber = sequenceNumber
        self.publicSettings = publicSettings
        self.protectedSettings = protectedSettings
        self.certificateThumbprint = certificateThumbprint
        self.dependencyLevel = dependencyLevel
        self.state = state


class ExtHandlerProperties(DataContract):
    def __init__(self):
        self.version = None
        self.state = None
        self.extensions = DataContractList(Extension)


class ExtHandlerVersionUri(DataContract):
    def __init__(self):
        self.uri = None


class ExtHandler(DataContract):
    """
    The main Plugin/handler specified by the publishers.
    Maps to Extension.PluginSettings.Plugins.Plugin in the ExtensionConfig.xml file
    Eg: Microsoft.OSTC.CustomScript
    """

    def __init__(self, name=None):
        self.name = name
        self.properties = ExtHandlerProperties()
        self.versionUris = DataContractList(ExtHandlerVersionUri)
        self.__invalid_handler_setting_reason = None

    @property
    def is_invalid_setting(self):
        return self.__invalid_handler_setting_reason is not None

    @property
    def invalid_setting_reason(self):
        return self.__invalid_handler_setting_reason

    @invalid_setting_reason.setter
    def invalid_setting_reason(self, value):
        self.__invalid_handler_setting_reason = value

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


class InVMGoalStateMetaData(DataContract):
    """
    Object for parsing the GoalState MetaData received from CRP
    Eg: <InVMGoalStateMetaData inSvdSeqNo="2" createdOnTicks="637405409304121230" activityId="555e551c-600e-4fb4-90ba-8ab8ec28eccc" correlationId="400de90b-522e-491f-9d89-ec944661f531" />
    """
    def __init__(self):
        self.in_svd_seq_no = None
        self.created_on_ticks = None
        self.activity_id = None
        self.correlation_id = None

    def parse_node(self, in_vm_metadata_node):

        def __ticks_to_datetime(ticks):
            if ticks in (None, ""):
                return None
            try:
                # C# ticks is a number of ticks since midnight 0001-01-01 00:00:00 (every tick is 1/10000000 of second)
                # and UNIX timestamp is number of seconds since beginning of the UNIX epoch (1970-01-01 01:00:00).
                # This function converts the ticks to datetime object that Python recognises.
                return datetime.min + timedelta(seconds=float(ticks) / 10 ** 7)
            except Exception:
                return None

        self.correlation_id = getattrib(in_vm_metadata_node, "correlationId")
        self.activity_id = getattrib(in_vm_metadata_node, "activityId")
        self.created_on_ticks = __ticks_to_datetime(getattrib(in_vm_metadata_node, "createdOnTicks"))
        self.in_svd_seq_no = getattrib(in_vm_metadata_node, "inSvdSeqNo")


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

