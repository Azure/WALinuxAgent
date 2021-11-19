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
import json
import re
import sys

from azurelinuxagent.common.exception import VmSettingsError
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState
from azurelinuxagent.common.protocol.restapi import VMAgentManifest
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import format_exception


class ExtensionsGoalStateFromVmSettings(ExtensionsGoalState):
    def __init__(self, etag, json_text):
        super(ExtensionsGoalStateFromVmSettings, self).__init__()
        self._id = etag
        self._text = json_text
        self._host_ga_plugin_version = FlexibleVersion('0.0.0.0')
        self._schema_version = FlexibleVersion('0.0.0.0')
        self._activity_id = None
        self._correlation_id = None
        self._created_on_timestamp = None
        self._source = None
        self._status_upload_blob = None
        self._status_upload_blob_type = None
        self._required_features = []
        self._on_hold = False
        self._agent_manifests = []

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
    def ext_handlers(self):
        # TODO - Implement this
        raise NotImplementedError()

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
            uris = family["uris"]
            manifest = VMAgentManifest(name)
            for u in uris:
                manifest.uris.append(u)
            self._agent_manifests.append(manifest)

    def _parse_extensions(self, vm_settings):
        # TODO: Implement this
        pass


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





