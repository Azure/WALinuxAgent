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

from collections import defaultdict

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ExtensionsConfigError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateChannel, GoalStateSource
from azurelinuxagent.common.protocol.restapi import ExtensionSettings, Extension, VMAgentManifest, ExtensionState, InVMGoalStateMetaData
from azurelinuxagent.common.utils.textutil import parse_doc, parse_json, findall, find, findtext, getattrib, gettext, format_exception, \
    is_str_none_or_whitespace, is_str_empty


class ExtensionsGoalStateFromExtensionsConfig(ExtensionsGoalState):
    def __init__(self, incarnation, xml_text, wire_client):
        super(ExtensionsGoalStateFromExtensionsConfig, self).__init__()
        self._id = "incarnation_{0}".format(incarnation)
        self._is_outdated = False
        self._incarnation = incarnation
        self._text = xml_text
        self._status_upload_blob = None
        self._status_upload_blob_type = None
        self._required_features = []
        self._on_hold = False
        self._activity_id = None
        self._correlation_id = None
        self._created_on_timestamp = None
        self._agent_manifests = []
        self._extensions = []

        try:
            self._parse_extensions_config(xml_text, wire_client)
            self._do_common_validations()
        except Exception as e:
            raise ExtensionsConfigError("Error parsing ExtensionsConfig (incarnation: {0}): {1}\n{2}".format(incarnation, format_exception(e), self.get_redacted_text()))

    def _parse_extensions_config(self, xml_text, wire_client):
        xml_doc = parse_doc(xml_text)

        ga_families_list = find(xml_doc, "GAFamilies")
        ga_families = findall(ga_families_list, "GAFamily")

        for ga_family in ga_families:
            family = findtext(ga_family, "Name")
            version = findtext(ga_family, "Version")
            uris_list = find(ga_family, "Uris")
            uris = findall(uris_list, "Uri")
            manifest = VMAgentManifest(family, version)
            for uri in uris:
                manifest.uris.append(gettext(uri))
            self._agent_manifests.append(manifest)

        self.__parse_plugins_and_settings_and_populate_ext_handlers(xml_doc)

        required_features_list = find(xml_doc, "RequiredFeatures")
        if required_features_list is not None:
            self._parse_required_features(required_features_list)

        self._status_upload_blob = findtext(xml_doc, "StatusUploadBlob")

        status_upload_node = find(xml_doc, "StatusUploadBlob")
        self._status_upload_blob_type = getattrib(status_upload_node, "statusBlobType")
        logger.verbose("Extension config shows status blob type as [{0}]", self._status_upload_blob_type)

        self._on_hold = self._fetch_extensions_on_hold(xml_doc, wire_client)

        in_vm_gs_metadata = InVMGoalStateMetaData(find(xml_doc, "InVMGoalStateMetaData"))
        self._activity_id = self._string_to_id(in_vm_gs_metadata.activity_id)
        self._correlation_id = self._string_to_id(in_vm_gs_metadata.correlation_id)
        self._created_on_timestamp = self._ticks_to_utc_timestamp(in_vm_gs_metadata.created_on_ticks)

    def _fetch_extensions_on_hold(self, xml_doc, wire_client):
        artifacts_profile_blob = findtext(xml_doc, "InVMArtifactsProfileBlob")
        if is_str_none_or_whitespace(artifacts_profile_blob):
            return False

        def fetch_direct():
            content, _ = wire_client.fetch(artifacts_profile_blob)
            return content

        def fetch_through_host():
            host = wire_client.get_host_plugin()
            uri, headers = host.get_artifact_request(artifacts_profile_blob)
            content, _ = wire_client.fetch(uri, headers, use_proxy=False)
            return content

        logger.verbose("Retrieving the artifacts profile")

        try:
            profile = wire_client.send_request_using_appropriate_channel(fetch_direct, fetch_through_host)
            if profile is None:
                logger.warn("Failed to fetch artifacts profile from blob {0}", artifacts_profile_blob)
                return False
        except Exception as error:
            logger.warn("Exception retrieving artifacts profile from blob {0}. Error: {1}".format(artifacts_profile_blob, ustr(error)))
            return False

        if is_str_empty(profile):
            return False

        logger.verbose("Artifacts profile downloaded")

        try:
            artifacts_profile = _InVMArtifactsProfile(profile)
        except Exception:
            logger.warn("Could not parse artifacts profile blob")
            msg = "Content: [{0}]".format(profile)
            logger.verbose(msg)
            add_event(op=WALAEventOperation.ArtifactsProfileBlob, is_success=False, message=msg, log_event=False)
            return False

        return artifacts_profile.get_on_hold()

    @property
    def id(self):
        return self._id

    @property
    def incarnation(self):
        return self._incarnation

    @property
    def svd_sequence_number(self):
        return self._incarnation

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
    def channel(self):
        return GoalStateChannel.WireServer

    @property
    def source(self):
        return GoalStateSource.Fabric

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
        text = self._text
        for ext_handler in self._extensions:
            for extension in ext_handler.settings:
                if extension.protectedSettings is not None:
                    text = text.replace(extension.protectedSettings, "*** REDACTED ***")
        return text

    def _parse_required_features(self, required_features_list):
        for required_feature in findall(required_features_list, "RequiredFeature"):
            feature_name = findtext(required_feature, "Name")
            # per the documentation, RequiredFeatures also have a "Value" attribute but currently it is not being populated
            self._required_features.append(feature_name)

    def __parse_plugins_and_settings_and_populate_ext_handlers(self, xml_doc):
        """
        Sample ExtensionConfig Plugin and PluginSettings:

        <Plugins>
          <Plugin name="Microsoft.CPlat.Core.NullSeqB" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbz06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true" />
          <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbn06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true" />
        </Plugins>
        <PluginSettings>
          <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1">
            <DependsOn dependencyLevel="1">
              <DependsOnExtension handler="Microsoft.CPlat.Core.NullSeqB" />
            </DependsOn>
            <RuntimeSettings seqNo="0">{
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"01_add_extensions_with_dependency":"ff2a3da6-8e12-4ab6-a4ca-4e3a473ab385"}
                  }
                }
              ]
            }
            </RuntimeSettings>
          </Plugin>
          <Plugin name="Microsoft.CPlat.Core.NullSeqB" version="2.0.1">
            <RuntimeSettings seqNo="0">{
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"01_add_extensions_with_dependency":"2e837740-cf7e-4528-b3a4-241002618f05"}
                  }
                }
              ]
            }
            </RuntimeSettings>
          </Plugin>
        </PluginSettings>
        """

        plugins_list = find(xml_doc, "Plugins")
        plugins = findall(plugins_list, "Plugin")
        plugin_settings_list = find(xml_doc, "PluginSettings")
        plugin_settings = findall(plugin_settings_list, "Plugin")

        for plugin in plugins:
            extension = Extension()
            try:
                ExtensionsGoalStateFromExtensionsConfig._parse_plugin(extension, plugin)
                ExtensionsGoalStateFromExtensionsConfig._parse_plugin_settings(extension, plugin_settings)
            except ExtensionsConfigError as error:
                extension.invalid_setting_reason = ustr(error)

            self._extensions.append(extension)

    @staticmethod
    def _parse_plugin(extension, plugin):
        """
        Sample config:

        <Plugins>
          <Plugin name="Microsoft.CPlat.Core.NullSeqB" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbz06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true"><Plugin name="Microsoft.Azure.Extensions.CustomScript" version="1.0" location="https://rdfecurrentuswestcache.blob.core.test-cint.azure-test.net/0e53c53ef0be4178bacb0a1fecf12a74/Microsoft.Azure.Extensions_CustomScript_usstagesc_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://rdfecurrentuswestcache2.blob.core.test-cint.azure-test.net/0e53c53ef0be4178bacb0a1fecf12a74/Microsoft.Azure.Extensions_CustomScript_usstagesc_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true">
            <additionalLocations>
              <additionalLocation>https://rdfecurrentuswestcache3.blob.core.test-cint.azure-test.net/0e53c53ef0be4178bacb0a1fecf12a74/Microsoft.Azure.Extensions_CustomScript_usstagesc_manifest.xml</additionalLocation>
              <additionalLocation>https://rdfecurrentuswestcache4.blob.core.test-cint.azure-test.net/0e53c53ef0be4178bacb0a1fecf12a74/Microsoft.Azure.Extensions_CustomScript_usstagesc_manifest.xml</additionalLocation>
            </additionalLocations>
          </Plugin>
          <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbn06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true" />
        </Plugins>


        Note that the `additionalLocations` subnode is populated with links
        generated by PIR for resiliency. In regions with this feature enabled,
        CRP will provide any extra links in the format above. If no extra links
        are provided, the subnode will not exist.
        """

        def _log_error_if_none(attr_name, value):
            # Plugin Name and Version are very essential fields, without them we wont be able to even report back to CRP
            # about that handler. For those cases we need to fail the GoalState completely but currently we dont support
            # reporting status at a GoalState level (we only report at a handler level).
            # Once that functionality is added to the GA, we would raise here rather than just report error in our logs.
            if value in (None, ""):
                add_event(op=WALAEventOperation.InvalidExtensionConfig,
                          message="{0} is None for ExtensionConfig, logging error".format(attr_name),
                          log_event=True, is_success=False)
            return value

        extension.name = _log_error_if_none("Extensions.Plugins.Plugin.name", getattrib(plugin, "name"))
        extension.version = _log_error_if_none("Extensions.Plugins.Plugin.version",
                                                            getattrib(plugin, "version"))
        extension.state = getattrib(plugin, "state")
        if extension.state in (None, ""):
            raise ExtensionsConfigError("Received empty Extensions.Plugins.Plugin.state, failing Handler")

        def getattrib_wrapped_in_list(node, attr_name):
            attr = getattrib(node, attr_name)
            return [attr] if attr not in (None, "") else []

        location = getattrib_wrapped_in_list(plugin, "location")
        failover_location = getattrib_wrapped_in_list(plugin, "failoverlocation")

        locations = location + failover_location

        additional_location_node = find(plugin, "additionalLocations")
        if additional_location_node is not None:
            nodes_list = findall(additional_location_node, "additionalLocation")
            locations += [gettext(node) for node in nodes_list]

        for uri in locations:
            extension.manifest_uris.append(uri)

    @staticmethod
    def _parse_plugin_settings(extension, plugin_settings):
        """
        Sample config:

        <PluginSettings>
            <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1">
                <DependsOn dependencyLevel="1">
                  <DependsOnExtension handler="Microsoft.CPlat.Core.NullSeqB" />
                </DependsOn>
                <RuntimeSettings seqNo="0">{
                  "runtimeSettings": [
                    {
                      "handlerSettings": {
                        "publicSettings": {"01_add_extensions_with_dependency":"ff2a3da6-8e12-4ab6-a4ca-4e3a473ab385"}
                      }
                    }
                  ]
                }
                </RuntimeSettings>
            </Plugin>
            <Plugin name="Microsoft.CPlat.Core.RunCommandHandlerWindows" version="2.0.2">
                <ExtensionRuntimeSettings seqNo="4" name="firstRunCommand" state="enabled">{
                  "runtimeSettings": [
                    {
                      "handlerSettings": {
                        "publicSettings": {"source":{"script":"Write-Host First: Hello World TestTry2!"},"parameters":[{"name":"extensionName","value":"firstRunCommand"}],"timeoutInSeconds":120}
                      }
                    }
                  ]
                }
                </ExtensionRuntimeSettings>
            </Plugin>
        </PluginSettings>
        """
        if plugin_settings is None:
            return

        extension_name = extension.name
        version = extension.version

        def to_lower(str_to_change): return str_to_change.lower() if str_to_change is not None else None

        extension_plugin_settings = [x for x in plugin_settings if to_lower(getattrib(x, "name")) == to_lower(extension_name)]
        if not extension_plugin_settings:
            return

        settings = [x for x in extension_plugin_settings if getattrib(x, "version") == version]
        if len(settings) != len(extension_plugin_settings):
            msg = "Extension PluginSettings Version Mismatch! Expected PluginSettings version: {0} for Extension: {1} but found versions: ({2})".format(
                version, extension_name, ', '.join(set([getattrib(x, "version") for x in extension_plugin_settings])))
            add_event(op=WALAEventOperation.PluginSettingsVersionMismatch, message=msg, log_event=True,
                      is_success=False)
            raise ExtensionsConfigError(msg)

        if len(settings) > 1:
            msg = "Multiple plugin settings found for the same extension: {0} and version: {1} (Expected: 1; Available: {2})".format(
                extension_name, version, len(settings))
            raise ExtensionsConfigError(msg)

        plugin_settings_node = settings[0]
        runtime_settings_nodes = findall(plugin_settings_node, "RuntimeSettings")
        extension_runtime_settings_nodes = findall(plugin_settings_node, "ExtensionRuntimeSettings")

        if any(runtime_settings_nodes) and any(extension_runtime_settings_nodes):
            # There can only be a single RuntimeSettings node or multiple ExtensionRuntimeSettings nodes per Plugin
            msg = "Both RuntimeSettings and ExtensionRuntimeSettings found for the same extension: {0} and version: {1}".format(
                extension_name, version)
            raise ExtensionsConfigError(msg)

        if runtime_settings_nodes:
            if len(runtime_settings_nodes) > 1:
                msg = "Multiple RuntimeSettings found for the same extension: {0} and version: {1} (Expected: 1; Available: {2})".format(
                    extension_name, version, len(runtime_settings_nodes))
                raise ExtensionsConfigError(msg)
            # Only Runtime settings available, parse that
            ExtensionsGoalStateFromExtensionsConfig.__parse_runtime_settings(plugin_settings_node, runtime_settings_nodes[0], extension_name,
                                                                             extension)
        elif extension_runtime_settings_nodes:
            # Parse the ExtensionRuntime settings for the given extension
            ExtensionsGoalStateFromExtensionsConfig.__parse_extension_runtime_settings(plugin_settings_node, extension_runtime_settings_nodes,
                                                                extension)

    @staticmethod
    def __get_dependency_level_from_node(depends_on_node, name):
        depends_on_level = 0
        if depends_on_node is not None:
            try:
                depends_on_level = int(getattrib(depends_on_node, "dependencyLevel"))
            except (ValueError, TypeError):
                logger.warn("Could not parse dependencyLevel for handler {0}. Setting it to 0".format(name))
                depends_on_level = 0
        return depends_on_level

    @staticmethod
    def __parse_runtime_settings(plugin_settings_node, runtime_settings_node, extension_name, extension):
        """
        Sample Plugin in PluginSettings containing DependsOn and RuntimeSettings (single settings per extension) -

        <Plugin name="Microsoft.Compute.VMAccessAgent" version="2.4.7">
        <DependsOn dependencyLevel="2">
          <DependsOnExtension extension="firstRunCommand" handler="Microsoft.CPlat.Core.RunCommandHandlerWindows" />
          <DependsOnExtension handler="Microsoft.Compute.CustomScriptExtension" />
        </DependsOn>
        <RuntimeSettings seqNo="1">{
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "protectedSettingsCertThumbprint": "<Redacted>",
                    "protectedSettings": "<Redacted>",
                    "publicSettings": {"UserName":"test1234"}
                  }
                }
              ]
            }
        </RuntimeSettings>
        </Plugin>
        """
        depends_on_nodes = findall(plugin_settings_node, "DependsOn")
        if len(depends_on_nodes) > 1:
            msg = "Extension Handler can only have a single dependsOn node for Single config extensions. Found: {0}".format(
                len(depends_on_nodes))
            raise ExtensionsConfigError(msg)
        depends_on_node = depends_on_nodes[0] if depends_on_nodes else None
        depends_on_level = ExtensionsGoalStateFromExtensionsConfig.__get_dependency_level_from_node(depends_on_node, extension_name)
        ExtensionsGoalStateFromExtensionsConfig.__parse_and_add_extension_settings(runtime_settings_node, extension_name, extension,
                                                                                   depends_on_level)

    @staticmethod
    def __parse_extension_runtime_settings(plugin_settings_node, extension_runtime_settings_nodes, extension):
        """
        Sample PluginSettings containing DependsOn and ExtensionRuntimeSettings -

        <Plugin name="Microsoft.CPlat.Core.RunCommandHandlerWindows" version="2.0.2">
        <DependsOn dependencyLevel="3" name="secondRunCommand">
          <DependsOnExtension extension="firstRunCommand" handler="Microsoft.CPlat.Core.RunCommandHandlerWindows" />
          <DependsOnExtension handler="Microsoft.Compute.CustomScriptExtension" />
          <DependsOnExtension handler="Microsoft.Compute.VMAccessAgent" />
        </DependsOn>
        <DependsOn dependencyLevel="4" name="thirdRunCommand">
          <DependsOnExtension extension="firstRunCommand" handler="Microsoft.CPlat.Core.RunCommandHandlerWindows" />
          <DependsOnExtension extension="secondRunCommand" handler="Microsoft.CPlat.Core.RunCommandHandlerWindows" />
          <DependsOnExtension handler="Microsoft.Compute.CustomScriptExtension" />
          <DependsOnExtension handler="Microsoft.Compute.VMAccessAgent" />
        </DependsOn>
        <ExtensionRuntimeSettings seqNo="2" name="firstRunCommand" state="enabled">
            {
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"source":{"script":"Write-Host First: Hello World 1234!"}}
                  }
                }
              ]
            }
        </ExtensionRuntimeSettings>
        <ExtensionRuntimeSettings seqNo="2" name="secondRunCommand" state="enabled">
            {
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"source":{"script":"Write-Host First: Hello World 1234!"}}
                  }
                }
              ]
            }
        </ExtensionRuntimeSettings>
        <ExtensionRuntimeSettings seqNo="1" name="thirdRunCommand" state="enabled">
            {
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"source":{"script":"Write-Host Third: Hello World 3!"}}
                  }
                }
              ]
            }
        </ExtensionRuntimeSettings>
      </Plugin>
        """
        # Parse and cache the Dependencies for each extension first
        dependency_levels = defaultdict(int)
        for depends_on_node in findall(plugin_settings_node, "DependsOn"):
            extension_name = getattrib(depends_on_node, "name")
            if extension_name in (None, ""):
                raise ExtensionsConfigError("No Name not specified for DependsOn object in ExtensionRuntimeSettings for MultiConfig!")

            dependency_level = ExtensionsGoalStateFromExtensionsConfig.__get_dependency_level_from_node(depends_on_node, extension_name)
            dependency_levels[extension_name] = dependency_level

        extension.supports_multi_config = True
        for extension_runtime_setting_node in extension_runtime_settings_nodes:
            # Name and State will only be set for ExtensionRuntimeSettings for Multi-Config
            extension_name = getattrib(extension_runtime_setting_node, "name")
            if extension_name in (None, ""):
                raise ExtensionsConfigError("Extension Name not specified for ExtensionRuntimeSettings for MultiConfig!")
            # State can either be `ExtensionState.Enabled` (default) or `ExtensionState.Disabled`
            state = getattrib(extension_runtime_setting_node, "state")
            state = ustr(state.lower()) if state not in (None, "") else ExtensionState.Enabled
            ExtensionsGoalStateFromExtensionsConfig.__parse_and_add_extension_settings(extension_runtime_setting_node, extension_name,
                                                                extension, dependency_levels[extension_name],
                                                                state=state)

    @staticmethod
    def __parse_and_add_extension_settings(settings_node, name, extension, depends_on_level, state=ExtensionState.Enabled):
        seq_no = getattrib(settings_node, "seqNo")
        if seq_no in (None, ""):
            raise ExtensionsConfigError("SeqNo not specified for the Extension: {0}".format(name))

        try:
            runtime_settings = json.loads(gettext(settings_node))
        except ValueError as error:
            logger.error("Invalid extension settings: {0}", ustr(error))
            # Incase of invalid/no settings, add the name and seqNo of the Extension and treat it as an extension with
            # no settings since we were able to successfully parse those data properly. Without this, we wont report
            # anything for that sequence number and CRP would eventually have to timeout rather than fail fast.
            extension.settings.append(
                ExtensionSettings(name=name, sequenceNumber=seq_no, state=state, dependencyLevel=depends_on_level))
            return

        for plugin_settings_list in runtime_settings["runtimeSettings"]:
            handler_settings = plugin_settings_list["handlerSettings"]
            extension_settings = ExtensionSettings()
            # There is no "extension name" for single Handler Settings. Use HandlerName for those
            extension_settings.name = name
            extension_settings.state = state
            extension_settings.sequenceNumber = int(seq_no)
            extension_settings.publicSettings = handler_settings.get("publicSettings")
            extension_settings.protectedSettings = handler_settings.get("protectedSettings")
            extension_settings.dependencyLevel = depends_on_level
            thumbprint = handler_settings.get("protectedSettingsCertThumbprint")
            extension_settings.certificateThumbprint = thumbprint
            extension.settings.append(extension_settings)


# Do not extend this class
class _InVMArtifactsProfile(object):
    """
    deserialized json string of InVMArtifactsProfile.
    It is expected to contain the following fields:
    * inVMArtifactsProfileBlobSeqNo
    * profileId (optional)
    * onHold (optional)
    * certificateThumbprint (optional)
    * encryptedHealthChecks (optional)
    * encryptedApplicationProfile (optional)
    """

    def __init__(self, artifacts_profile_json):
        self._on_hold = False
        artifacts_profile = parse_json(artifacts_profile_json)
        on_hold = artifacts_profile.get('onHold')
        if on_hold is not None:
            # accept both bool and str values
            on_hold_normalized = str(on_hold).lower()
            if on_hold_normalized == "true":
                self._on_hold = True
            elif on_hold_normalized == "false":
                self._on_hold = False
            else:
                raise Exception("Invalid value for onHold: {0}".format(on_hold))

    def get_on_hold(self):
        return self._on_hold

