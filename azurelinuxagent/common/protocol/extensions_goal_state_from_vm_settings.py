# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
import datetime
import json
import re
import sys

from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import VmSettingsError
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState
from azurelinuxagent.common.protocol.restapi import VMAgentManifest, Extension, ExtensionRequestedState, ExtensionSettings
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import format_exception


class ExtensionsGoalStateFromVmSettings(ExtensionsGoalState):
    _MINIMUM_TIMESTAMP = datetime.datetime(1900, 1, 1, 0, 0)  # min value accepted by datetime.strftime()

    def __init__(self, etag, json_text):
        super(ExtensionsGoalStateFromVmSettings, self).__init__()
        self._id = etag
        self._text = json_text
        self._host_ga_plugin_version = FlexibleVersion('0.0.0.0')
        self._schema_version = FlexibleVersion('0.0.0.0')
        self._activity_id = AgentGlobals.GUID_ZERO
        self._correlation_id = AgentGlobals.GUID_ZERO
        self._created_on_timestamp = self._MINIMUM_TIMESTAMP
        self._source = None
        self._status_upload_blob = None
        self._status_upload_blob_type = None
        self._required_features = []
        self._on_hold = False
        self._agent_manifests = []
        self._extensions = []

        try:
            self._parse_vm_settings(json_text)
            self._do_common_validations()
        except Exception as e:
            raise VmSettingsError("Error parsing vmSettings (etag: {0}): {1}\n{2}".format(etag, format_exception(e), self.get_redacted_text()))

    @property
    def id(self):
        return self._id

    @property
    def host_ga_plugin_version(self):
        return self._host_ga_plugin_version

    @property
    def schema_version(self):
        return self._schema_version

    @property
    def activity_id(self):
        return self._activity_id

    @property
    def correlation_id(self):
        return self._correlation_id

    @property
    def created_on_timestamp(self):
        return self._created_on_timestamp

    @property
    def source(self):
        """
        Whether the goal state originated from Fabric or Fast Track
        """
        return self._source

    @property
    def status_upload_blob(self):
        return self._status_upload_blob

    @property
    def status_upload_blob_type(self):
        return self._status_upload_blob_type

    def _set_status_upload_blob_type(self, value):
        self._status_upload_blob_type = value

    @property
    def required_features(self):
        return self._required_features

    @property
    def on_hold(self):
        return self._on_hold

    @property
    def agent_manifests(self):
        return self._agent_manifests

    @property
    def extensions(self):
        return self._extensions

    def get_redacted_text(self):
        return re.sub(r'("protectedSettings"\s*:\s*)"[^"]+"', r'\1"*** REDACTED ***"', self._text)

    def _parse_vm_settings(self, json_text):
        vm_settings = _CaseFoldedDict.from_dict(json.loads(json_text))
        self._parse_simple_attributes(vm_settings)
        self._parse_status_upload_blob(vm_settings)
        self._parse_required_features(vm_settings)
        self._parse_agent_manifests(vm_settings)
        self._parse_extensions(vm_settings)

    def _parse_simple_attributes(self, vm_settings):
        # Sample:
        #     {
        #         "hostGAPluginVersion": "1.0.8.115",
        #         "vmSettingsSchemaVersion": "0.0",
        #         "activityId": "a33f6f53-43d6-4625-b322-1a39651a00c9",
        #         "correlationId": "9a47a2a2-e740-4bfc-b11b-4f2f7cfe7d2e",
        #         "extensionsLastModifiedTickCount": 637726657706205217,
        #         "extensionGoalStatesSource": "Fabric",
        #         ...
        #     }
        self._activity_id = self._string_to_id(vm_settings.get("activityId"))
        self._correlation_id = self._string_to_id(vm_settings.get("correlationId"))
        self._created_on_timestamp = self._ticks_to_utc_timestamp(vm_settings.get("extensionsLastModifiedTickCount"))

        host_ga_plugin_version = vm_settings.get("hostGAPluginVersion")
        if host_ga_plugin_version is not None:
            self._host_ga_plugin_version = FlexibleVersion(host_ga_plugin_version)

        schema_version = vm_settings.get("vmSettingsSchemaVersion")
        if schema_version is not None:
            self._schema_version = FlexibleVersion(schema_version)

        on_hold = vm_settings.get("onHold")
        if on_hold is not None:
            self._on_hold = on_hold

        self._source = vm_settings.get("extensionGoalStatesSource")
        if self._source is None:
            self._source = "UNKNOWN"

    def _parse_status_upload_blob(self, vm_settings):
        # Sample:
        # {
        #     ...
        #     "statusUploadBlob": {
        #         "statusBlobType": "BlockBlob",
        #         "value": "https://dcrcl3a0xs.blob.core.windows.net/$system/edp0plkw2b.86f4ae0a-61f8-48ae-9199-40f402d56864.status?sv=2018-03-28&sr=b&sk=system-1&sig=KNWgC2%3d&se=9999-01-01T00%3a00%3a00Z&sp=w"
        #     },
        #     ...
        # }
        status_upload_blob = vm_settings.get("statusUploadBlob")
        if status_upload_blob is None:
            raise Exception("Missing statusUploadBlob")
        self._status_upload_blob = status_upload_blob.get("value")
        if self._status_upload_blob is None:
            raise Exception("Missing statusUploadBlob.value")
        self._status_upload_blob_type = status_upload_blob.get("statusBlobType")
        if self._status_upload_blob is None:
            raise Exception("Missing statusUploadBlob.statusBlobType")

    def _parse_required_features(self, vm_settings):
        # Sample:
        # {
        #     ...
        #     "requiredFeatures": [
        #         {
        #             "name": "MultipleExtensionsPerHandler"
        #         }
        #     ],
        #     ...
        # }
        required_features = vm_settings.get("requiredFeatures")
        if required_features is not None:
            if not isinstance(required_features, list):
                raise Exception("requiredFeatures should be an array")

            def get_required_features_names():
                for feature in required_features:
                    name = feature.get("name")
                    if name is None:
                        raise Exception("A required feature is missing the 'name' property")
                    yield name

            self._required_features.extend(get_required_features_names())

    def _parse_agent_manifests(self, vm_settings):
        # Sample:
        # {
        #     ...
        #     "gaFamilies": [
        #         {
        #             "name": "Prod",
        #             "version": "9.9.9.9",
        #             "uris": [
        #                 "https://zrdfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml",
        #                 "https://ardfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml"
        #             ]
        #         },
        #         {
        #             "name": "Test",
        #             "uris": [
        #                 "https://zrdfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Test_uscentraleuap_manifest.xml",
        #                 "https://ardfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Test_uscentraleuap_manifest.xml"
        #             ]
        #         }
        #     ],
        #     ...
        # }
        families = vm_settings.get("gaFamilies")
        if families is None:
            return
        if not isinstance(families, list):
            raise Exception("gaFamilies should be an array")

        for family in families:
            name = family["name"]
            version = family.get("version")
            uris = family["uris"]
            manifest = VMAgentManifest(name, version)
            for u in uris:
                manifest.uris.append(u)
            self._agent_manifests.append(manifest)

    def _parse_extensions(self, vm_settings):
        # Sample (NOTE: The first sample is single-config, the second multi-config):
        # {
        #     ...
        #     "extensionGoalStates": [
        #         {
        #             "name": "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent",
        #             "version": "1.9.1",
        #             "location": "https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/a47f0806d764480a8d989d009c75007d/Microsoft.Azure.Monitor_AzureMonitorLinuxAgent_useast2euap_manifest.xml",
        #             "state": "enabled",
        #             "autoUpgrade": true,
        #             "runAsStartupTask": false,
        #             "isJson": true,
        #             "useExactVersion": true,
        #             "settingsSeqNo": 0,
        #             "settings": [
        #                 {
        #                     "protectedSettingsCertThumbprint": "4C4F304667711036E64AF4894B76EB208A863BD4",
        #                     "protectedSettings": "MIIBsAYJKoZIhvcNAQcDoIIBoTCCAZ0CAQAxggFpMIIBZQIBADBNMDkxNzA1BgoJkiaJk/IsZAEZFidXaW5kb3dzIEF6dXJlIENSUCBDZXJ0aWZpY2F0ZSBHZW5lcmF0b3ICEFpB/HKM/7evRk+DBz754wUwDQYJKoZIhvcNAQEBBQAEggEADPJwniDeIUXzxNrZCloitFdscQ59Bz1dj9DLBREAiM8jmxM0LLicTJDUv272Qm/4ZQgdqpFYBFjGab/9MX+Ih2x47FkVY1woBkckMaC/QOFv84gbboeQCmJYZC/rZJdh8rCMS+CEPq3uH1PVrvtSdZ9uxnaJ+E4exTPPviIiLIPtqWafNlzdbBt8HZjYaVw+SSe+CGzD2pAQeNttq3Rt/6NjCzrjG8ufKwvRoqnrInMs4x6nnN5/xvobKIBSv4/726usfk8Ug+9Q6Benvfpmre2+1M5PnGTfq78cO3o6mI3cPoBUjp5M0iJjAMGeMt81tyHkimZrEZm6pLa4NQMOEjArBgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECC5nVaiJaWt+gAhgeYvxUOYHXw==",
        #                     "publicSettings": "{\"GCS_AUTO_CONFIG\":true}"
        #                 }
        #             ],
        #             "dependsOn": [
        #                 {
        #                     "DependsOnExtension": [
        #                         {
        #                             "handler": "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent"
        #                         }
        #                     ],
        #                     "dependencyLevel": 1
        #                 }
        #            ]
        #         },
        #         {
        #             "name": "Microsoft.CPlat.Core.RunCommandHandlerLinux",
        #             "version": "1.2.0",
        #             "location": "https://umsavbvncrpzbnxmxzmr.blob.core.windows.net/f4086d41-69f9-3103-78e0-8a2c7e789d0f/f4086d41-69f9-3103-78e0-8a2c7e789d0f_manifest.xml",
        #             "failoverlocation": "https://umsajbjtqrb3zqjvgb2z.blob.core.windows.net/f4086d41-69f9-3103-78e0-8a2c7e789d0f/f4086d41-69f9-3103-78e0-8a2c7e789d0f_manifest.xml",
        #             "additionalLocations": [
        #                 "https://umsawqtlsshtn5v2nfgh.blob.core.windows.net/f4086d41-69f9-3103-78e0-8a2c7e789d0f/f4086d41-69f9-3103-78e0-8a2c7e789d0f_manifest.xml"
        #             ],
        #             "state": "enabled",
        #             "autoUpgrade": true,
        #             "runAsStartupTask": false,
        #             "isJson": true,
        #             "useExactVersion": true,
        #             "settingsSeqNo": 0,
        #             "isMultiConfig": true,
        #             "settings": [
        #                 {
        #                     "publicSettings": "{\"source\":{\"script\":\"echo '4abb1e88-f349-41f8-8442-247d9fdfcac5'\"}}",
        #                     "seqNo": 0,
        #                     "extensionName": "MCExt1",
        #                     "extensionState": "enabled"
        #                 },
        #                 {
        #                     "publicSettings": "{\"source\":{\"script\":\"echo 'e865c9bc-a7b3-42c6-9a79-cfa98a1ee8b3'\"}}",
        #                     "seqNo": 0,
        #                     "extensionName": "MCExt2",
        #                     "extensionState": "enabled"
        #                 },
        #                 {
        #                     "publicSettings": "{\"source\":{\"script\":\"echo 'f923e416-0340-485c-9243-8b84fb9930c6'\"}}",
        #                     "seqNo": 0,
        #                     "extensionName": "MCExt3",
        #                     "extensionState": "enabled"
        #                 }
        #             ]
        #         }
        #         ...
        #     ]
        #     ...
        # }
        extension_goal_states = vm_settings.get("extensionGoalStates")
        if extension_goal_states is not None:
            if not isinstance(extension_goal_states, list):
                raise Exception("extension_goal_states should be an array")
            for extension_gs in extension_goal_states:
                extension = Extension()

                extension.name = extension_gs['name']
                extension.version = extension_gs['version']
                extension.state = extension_gs['state']
                if extension.state not in ExtensionRequestedState.All:
                    raise Exception('Invalid extension state: {0} ({1})'.format(extension.state, extension.name))
                is_multi_config = extension_gs.get('isMultiConfig')
                if is_multi_config is not None:
                    extension.supports_multi_config = is_multi_config
                extension.manifest_uris.append(extension_gs['location'])
                fail_over_location = extension_gs.get('failoverLocation')
                if fail_over_location is not None:
                    extension.manifest_uris.append(fail_over_location)
                additional_locations = extension_gs.get('additionalLocations')
                if additional_locations is not None:
                    if not isinstance(additional_locations, list):
                        raise Exception('additionalLocations should be an array')
                    extension.manifest_uris.extend(additional_locations)

                #
                # Settings
                #
                settings_list = extension_gs.get('settings')
                if settings_list is not None:
                    if not isinstance(settings_list, list):
                        raise Exception("'settings' should be an array (extension: {0})".format(extension.name))
                    if not extension.supports_multi_config and len(settings_list) > 1:
                        raise Exception("Single-config extension includes multiple settings (extension: {0})".format(extension.name))

                    for s in settings_list:
                        settings = ExtensionSettings()
                        public_settings = s.get('publicSettings')
                        settings.publicSettings = {} if public_settings is None else json.loads(public_settings)
                        # Note that protectedSettings and protectedSettingsCertThumbprint can be None (which would be serialized to the extension's settings file as null)
                        settings.protectedSettings = s.get('protectedSettings')
                        thumbprint = s.get('protectedSettingsCertThumbprint')
                        if thumbprint is None and settings.protectedSettings is not None:
                            raise Exception("The certificate thumbprint for protected settings is missing (extension: {0})".format(extension.name))
                        settings.certificateThumbprint = thumbprint

                        # in multi-config each settings have their own name, sequence number and state
                        if extension.supports_multi_config:
                            settings.name = s['extensionName']
                            settings.sequenceNumber = s['seqNo']
                            settings.state = s['extensionState']
                        else:
                            settings.name = extension.name
                            settings.sequenceNumber = extension_gs['settingsSeqNo']
                            settings.state = extension.state
                        extension.settings.append(settings)

                #
                # Dependency level
                #
                depends_on = extension_gs.get("dependsOn")
                if depends_on is not None:
                    if not isinstance(depends_on, list):
                        raise Exception('dependsOn should be an array')
                    if extension.supports_multi_config:
                        # TODO: Parse dependencies for multi-config extensions
                        pass
                    else:
                        if len(depends_on) != 1:
                            raise Exception('dependsOn should be an array with exactly one item for single-config extensions')
                        extension.settings[0].dependencyLevel = depends_on[0]['dependencyLevel']

                self._extensions.append(extension)


#
# TODO: The current implementation of the vmSettings API uses inconsistent cases on the names of the json items it returns.
#       To work around that, we use _CaseFoldedDict to query those json items in a case-insensitive matter, Do not use
#       _CaseFoldedDict for other purposes. Remove it once the vmSettings API is updated.
#
class _CaseFoldedDict(dict):
    @staticmethod
    def from_dict(dictionary):
        case_folded = _CaseFoldedDict()
        for key, value in dictionary.items():
            case_folded[key] = _CaseFoldedDict._to_case_folded_dict_item(value)
        return case_folded

    def get(self, key):
        return super(_CaseFoldedDict, self).get(_casefold(key))

    def has_key(self, key):
        return super(_CaseFoldedDict, self).get(_casefold(key))

    def __getitem__(self, key):
        return super(_CaseFoldedDict, self).__getitem__(_casefold(key))

    def __setitem__(self, key, value):
        return super(_CaseFoldedDict, self).__setitem__(_casefold(key), value)

    def __contains__(self, key):
        return  super(_CaseFoldedDict, self).__contains__(_casefold(key))

    @staticmethod
    def _to_case_folded_dict_item(item):
        if isinstance(item, dict):
            case_folded_dict = _CaseFoldedDict()
            for key, value in item.items():
                case_folded_dict[_casefold(key)] = _CaseFoldedDict._to_case_folded_dict_item(value)
            return case_folded_dict
        if isinstance(item, list):
            return [_CaseFoldedDict._to_case_folded_dict_item(list_item) for list_item in item]
        return item

    def copy(self):
        raise NotImplementedError()

    @staticmethod
    def fromkeys(*args, **kwargs):
        raise NotImplementedError()

    def pop(self, key, default=None):
        raise NotImplementedError()

    def setdefault(self, key, default=None):
        raise NotImplementedError()

    def update(self, E=None, **F):  # known special case of dict.update
        raise NotImplementedError()

    def __delitem__(self, *args, **kwargs):
        raise NotImplementedError()


# casefold() does not exist on Python 2 so we use lower() there
def _casefold(string):
    if sys.version_info[0] == 2:
        return type(string).lower(string)  # the type of "string" can be unicode or str
    # Class 'str' has no 'casefold' member (no-member) -- Disabled: This warning shows up on Python 2.7 pylint runs
    # but this code is actually not executed on Python 2.
    return str.casefold(string)  # pylint: disable=no-member





