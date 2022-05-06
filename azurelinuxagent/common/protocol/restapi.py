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
import time

from azurelinuxagent.common.datacontract import DataContract, DataContractList
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import getattrib
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME, CURRENT_VERSION


VERSION_0 = "0.0.0.0"


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


class VMAgentManifest(object):
    def __init__(self, family, version=None):
        self.family = family
        # This is the Requested version as specified by the Goal State, it defaults to 0.0.0.0 if not specified in GS
        self.__requested_version_string = VERSION_0 if version is None else version
        self.uris = []

    @property
    def requested_version(self):
        return FlexibleVersion(self.__requested_version_string)

    @property
    def is_requested_version_specified(self):
        """
        If we don't get any requested_version from the GS, we default it to 0.0.0.0.
        This property identifies if a requested Version was passed in the GS or not.
        """
        return self.requested_version > FlexibleVersion(VERSION_0)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "[family: '{0}' uris: {1}]".format(self.family, self.uris)


class ExtensionState(object):
    Enabled = ustr("enabled")
    Disabled = ustr("disabled")


class ExtensionRequestedState(object):
    """
    This is the state of the Handler as requested by the Goal State.
    CRP only supports 2 states as of now - Enabled and Uninstall
    Disabled was used for older XML extensions and we keep it to support backward compatibility.
    """
    Enabled = ustr("enabled")
    Disabled = ustr("disabled")
    Uninstall = ustr("uninstall")
    All = [Enabled, Disabled, Uninstall]


class ExtensionSettings(object):
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
                 state=ExtensionState.Enabled):
        self.name = name
        self.sequenceNumber = sequenceNumber
        self.publicSettings = publicSettings
        self.protectedSettings = protectedSettings
        self.certificateThumbprint = certificateThumbprint
        self.dependencyLevel = dependencyLevel
        self.state = state

    def dependency_level_sort_key(self, handler_state):
        level = self.dependencyLevel
        # Process uninstall or disabled before enabled, in reverse order
        # Prioritize Handler state and Extension state both when sorting extensions
        # remap 0 to -1, 1 to -2, 2 to -3, etc
        if handler_state != ExtensionRequestedState.Enabled or self.state != ExtensionState.Enabled:
            level = (0 - level) - 1

        return level

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{0}".format(self.name)


class Extension(object):
    """
    The main Plugin/handler specified by the publishers.
    Maps to Extension.PluginSettings.Plugins.Plugin in the ExtensionConfig.xml file
    Eg: Microsoft.OSTC.CustomScript
    """

    def __init__(self, name=None):
        self.name = name
        self.version = None
        self.state = None
        self.settings = []
        self.manifest_uris = []
        self.supports_multi_config = False
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

    def dependency_level_sort_key(self):
        levels = [e.dependencyLevel for e in self.settings]
        if len(levels) == 0:
            level = 0
        else:
            level = min(levels)
        # Process uninstall or disabled before enabled, in reverse order
        # remap 0 to -1, 1 to -2, 2 to -3, etc
        if self.state != u"enabled":
            level = (0 - level) - 1
        return level

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{0}-{1}".format(self.name, self.version)

class InVMGoalStateMetaData(DataContract):
    """
    Object for parsing the GoalState MetaData received from CRP
    Eg: <InVMGoalStateMetaData inSvdSeqNo="2" createdOnTicks="637405409304121230" activityId="555e551c-600e-4fb4-90ba-8ab8ec28eccc" correlationId="400de90b-522e-491f-9d89-ec944661f531" />
    """
    def __init__(self, in_vm_metadata_node):
        self.correlation_id = getattrib(in_vm_metadata_node, "correlationId")
        self.activity_id = getattrib(in_vm_metadata_node, "activityId")
        self.created_on_ticks = getattrib(in_vm_metadata_node, "createdOnTicks")
        self.in_svd_seq_no = getattrib(in_vm_metadata_node, "inSvdSeqNo")


class ExtHandlerPackage(DataContract):
    def __init__(self, version=None):
        self.version = version
        self.uris = []
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
                 name=None,
                 configurationAppliedTime=None,
                 operation=None,
                 status=None,
                 seq_no=None,
                 code=None,
                 message=None):
        self.name = name
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
        self.supports_multi_config = False
        self.extension_status = None


class VMAgentStatus(DataContract):
    def __init__(self, status=None, message=None, gs_aggregate_status=None, update_status=None):
        self.status = status
        self.message = message
        self.hostname = socket.gethostname()
        self.version = str(CURRENT_VERSION)
        self.osname = DISTRO_NAME
        self.osversion = DISTRO_VERSION
        self.extensionHandlers = DataContractList(ExtHandlerStatus)
        self.vm_artifacts_aggregate_status = VMArtifactsAggregateStatus(gs_aggregate_status)
        self.update_status = update_status
        self._supports_fast_track = False

    @property
    def supports_fast_track(self):
        return self._supports_fast_track

    def set_supports_fast_track(self, value):
        self._supports_fast_track = value


class VMStatus(DataContract):
    def __init__(self, status, message, gs_aggregate_status=None, vm_agent_update_status=None):
        self.vmAgent = VMAgentStatus(status=status, message=message, gs_aggregate_status=gs_aggregate_status,
                                     update_status=vm_agent_update_status)


class GoalStateAggregateStatus(DataContract):
    def __init__(self, seq_no, status=None, message="", code=None):
        self.message = message
        self.in_svd_seq_no = seq_no
        self.status = status
        self.code = code
        self.__utc_timestamp = time.gmtime()

    @property
    def processed_time(self):
        return self.__utc_timestamp


class VMArtifactsAggregateStatus(DataContract):
    def __init__(self, gs_aggregate_status=None):
        self.goal_state_aggregate_status = gs_aggregate_status


class RemoteAccessUser(DataContract):
    def __init__(self, name, encrypted_password, expiration):
        self.name = name
        self.encrypted_password = encrypted_password
        self.expiration = expiration


class RemoteAccessUsersList(DataContract):
    def __init__(self):
        self.users = DataContractList(RemoteAccessUser)


class VMAgentUpdateStatuses(object):
    Success = ustr("Success")
    Transitioning = ustr("Transitioning")
    Error = ustr("Error")
    Unknown = ustr("Unknown")


class VMAgentUpdateStatus(object):
    def __init__(self, expected_version, status=VMAgentUpdateStatuses.Success, message="", code=0):
        self.expected_version = expected_version
        self.status = status
        self.message = message
        self.code = code
