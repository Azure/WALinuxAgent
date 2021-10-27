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

from collections import defaultdict
from operator import attrgetter

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ExtensionsConfigError, VmSettingsError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandler, ExtHandlerList, ExtHandlerVersionUri, VMAgentManifest, \
    VMAgentManifestList, VMAgentManifestUri, InVMGoalStateMetaData, ExtensionState
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext, format_exception


class ExtensionsGoalState(object):
    """
    ExtensionsGoalState represents the extensions information in the goal state; that information can originate from
    ExtensionsConfig when the goal state is retrieved from the WireServe or from vmSettings when it is retrieved from
    the HostGAPlugin.

    NOTE: Do not instantiate this class directly, use one of the create_* methods instead.
    """
    def __init__(self):
        self._id = None
        self._text = None
        self.ext_handlers = ExtHandlerList()
        self.vmagent_manifests = VMAgentManifestList()
        self.in_vm_gs_metadata = InVMGoalStateMetaData()
        self._status_upload_blob = None
        self._status_upload_blob_type = None
        self.artifacts_profile_blob = None
        self._required_features = []

    @staticmethod
    def create_empty():
        return _EmptyExtensionsGoalState()

    @staticmethod
    def create_from_extensions_config(incarnation, xml_text):
        return _ExtensionsGoalStateFromExtensionsConfig(incarnation, xml_text)

    @staticmethod
    def create_from_vm_settings(etag, json_text):
        return _ExtensionsGoalStateFromVmSettings(etag, json_text)

    def get_id(self):
        """
        Returns the incarnation number if the ExtensionsGoalState was created from ExtensionsConfig, or the etag if it
        was created from vmSettings.
        """
        return self._id

    def get_redacted_text(self):
        """
        Returns the raw text (either the ExtensionsConfig or the vmSettings) with any confidential data removed, or an empty string for empty goal states.
        """
        raise NotImplementedError()

    def get_required_features(self):
        return self._required_features

    def get_status_upload_blob(self):
        return self._status_upload_blob

    def get_status_upload_blob_type(self):
        return self._status_upload_blob_type

    @staticmethod
    def compare(from_extensions_config, from_vm_settings):
        """
        Compares the two instances given as argument and logs a GoalStateMismatch message if they are different.

        NOTE: The order of the two instances is important for the debug info to be logged correctly (ExtensionsConfig first, vmSettings second)
        """
        def report_difference(attribute):
            message = "Mismatch in ExtensionsConfig (incarnation {0}) and vmSettings (etag {1}).\nAttribute: {2}\n{3} != {4}".format(
                from_extensions_config.get_id(), from_vm_settings.get_id(),
                attribute,
                attrgetter(attribute)(from_extensions_config), attrgetter(attribute)(from_vm_settings)
            )
            logger.info("[GoalStateMismatch] {0}", message)
            add_event(op=WALAEventOperation.GoalStateMismatch, is_success=False, message=message)

        if from_extensions_config.get_status_upload_blob() != from_vm_settings.get_status_upload_blob():
            report_difference("_status_upload_blob")
        if from_extensions_config.get_status_upload_blob_type() != from_vm_settings.get_status_upload_blob_type():
            report_difference("_status_upload_blob_type")
        if from_extensions_config.get_required_features() != from_vm_settings.get_required_features():
            report_difference("_required_features")

    def _do_common_validations(self):
        """
        Does validations common to vmSettings and ExtensionsConfig
        """
        if self._status_upload_blob_type not in ["BlockBlob", "PageBlob"]:
            logger.info("Status Blob type '{0}' is not valid, assuming BlockBlob", self._status_upload_blob)
            self._status_upload_blob_type = "BlockBlob"


class _EmptyExtensionsGoalState(ExtensionsGoalState):
    def get_redacted_text(self):
        return ''


class _ExtensionsGoalStateFromExtensionsConfig(ExtensionsGoalState):
    def __init__(self, incarnation, xml_text):
        super(_ExtensionsGoalStateFromExtensionsConfig, self).__init__()
        self._id = incarnation
        self._text = xml_text

        try:
            self._parse_extensions_config(xml_text)
            self._do_common_validations()
        except Exception as e:
            raise ExtensionsConfigError("Error parsing ExtensionsConfig (incarnation: {0}): {1}\n{2}".format(incarnation, format_exception(e), self.get_redacted_text()))

    def _parse_extensions_config(self, xml_text):
        xml_doc = parse_doc(xml_text)

        ga_families_list = find(xml_doc, "GAFamilies")
        ga_families = findall(ga_families_list, "GAFamily")

        for ga_family in ga_families:
            family = findtext(ga_family, "Name")
            uris_list = find(ga_family, "Uris")
            uris = findall(uris_list, "Uri")
            manifest = VMAgentManifest()
            manifest.family = family
            for uri in uris:
                manifest_uri = VMAgentManifestUri(uri=gettext(uri))
                manifest.versionsManifestUris.append(manifest_uri)
            self.vmagent_manifests.vmAgentManifests.append(manifest)

        self.__parse_plugins_and_settings_and_populate_ext_handlers(xml_doc)

        required_features_list = find(xml_doc, "RequiredFeatures")
        if required_features_list is not None:
            self._parse_required_features(required_features_list)

        self._status_upload_blob = findtext(xml_doc, "StatusUploadBlob")
        self.artifacts_profile_blob = findtext(xml_doc, "InVMArtifactsProfileBlob")

        status_upload_node = find(xml_doc, "StatusUploadBlob")
        self._status_upload_blob_type = getattrib(status_upload_node, "statusBlobType")
        logger.verbose("Extension config shows status blob type as [{0}]", self._status_upload_blob_type)

        self.in_vm_gs_metadata.parse_node(find(xml_doc, "InVMGoalStateMetaData"))

    def get_redacted_text(self):
        text = self._text
        for ext_handler in self.ext_handlers.extHandlers:
            for extension in ext_handler.properties.extensions:
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
            ext_handler = ExtHandler()
            try:
                _ExtensionsGoalStateFromExtensionsConfig._parse_plugin(ext_handler, plugin)
                _ExtensionsGoalStateFromExtensionsConfig._parse_plugin_settings(ext_handler, plugin_settings)
            except ExtensionsConfigError as error:
                ext_handler.invalid_setting_reason = ustr(error)

            self.ext_handlers.extHandlers.append(ext_handler)

    @staticmethod
    def _parse_plugin(ext_handler, plugin):
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

        ext_handler.name = _log_error_if_none("Extensions.Plugins.Plugin.name", getattrib(plugin, "name"))
        ext_handler.properties.version = _log_error_if_none("Extensions.Plugins.Plugin.version",
                                                            getattrib(plugin, "version"))
        ext_handler.properties.state = getattrib(plugin, "state")
        if ext_handler.properties.state in (None, ""):
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
            version_uri = ExtHandlerVersionUri()
            version_uri.uri = uri
            ext_handler.versionUris.append(version_uri)

    @staticmethod
    def _parse_plugin_settings(ext_handler, plugin_settings):
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

        handler_name = ext_handler.name
        version = ext_handler.properties.version

        def to_lower(str_to_change): return str_to_change.lower() if str_to_change is not None else None

        ext_handler_plugin_settings = [x for x in plugin_settings if to_lower(getattrib(x, "name")) == to_lower(handler_name)]
        if not ext_handler_plugin_settings:
            return

        settings = [x for x in ext_handler_plugin_settings if getattrib(x, "version") == version]
        if len(settings) != len(ext_handler_plugin_settings):
            msg = "ExtHandler PluginSettings Version Mismatch! Expected PluginSettings version: {0} for Handler: {1} but found versions: ({2})".format(
                version, handler_name, ', '.join(set([getattrib(x, "version") for x in ext_handler_plugin_settings])))
            add_event(op=WALAEventOperation.PluginSettingsVersionMismatch, message=msg, log_event=True,
                      is_success=False)
            raise ExtensionsConfigError(msg)

        if len(settings) > 1:
            msg = "Multiple plugin settings found for the same handler: {0} and version: {1} (Expected: 1; Available: {2})".format(
                handler_name, version, len(settings))
            raise ExtensionsConfigError(msg)

        plugin_settings_node = settings[0]
        runtime_settings_nodes = findall(plugin_settings_node, "RuntimeSettings")
        extension_runtime_settings_nodes = findall(plugin_settings_node, "ExtensionRuntimeSettings")

        if any(runtime_settings_nodes) and any(extension_runtime_settings_nodes):
            # There can only be a single RuntimeSettings node or multiple ExtensionRuntimeSettings nodes per Plugin
            msg = "Both RuntimeSettings and ExtensionRuntimeSettings found for the same handler: {0} and version: {1}".format(
                handler_name, version)
            raise ExtensionsConfigError(msg)

        if runtime_settings_nodes:
            if len(runtime_settings_nodes) > 1:
                msg = "Multiple RuntimeSettings found for the same handler: {0} and version: {1} (Expected: 1; Available: {2})".format(
                    handler_name, version, len(runtime_settings_nodes))
                raise ExtensionsConfigError(msg)
            # Only Runtime settings available, parse that
            _ExtensionsGoalStateFromExtensionsConfig.__parse_runtime_settings(plugin_settings_node, runtime_settings_nodes[0], handler_name,
                                                      ext_handler)
        elif extension_runtime_settings_nodes:
            # Parse the ExtensionRuntime settings for the given extension
            _ExtensionsGoalStateFromExtensionsConfig.__parse_extension_runtime_settings(plugin_settings_node, extension_runtime_settings_nodes,
                                                                ext_handler)

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
    def __parse_runtime_settings(plugin_settings_node, runtime_settings_node, handler_name, ext_handler):
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
        depends_on_level = _ExtensionsGoalStateFromExtensionsConfig.__get_dependency_level_from_node(depends_on_node, handler_name)
        _ExtensionsGoalStateFromExtensionsConfig.__parse_and_add_extension_settings(runtime_settings_node, handler_name, ext_handler,
                                                            depends_on_level)

    @staticmethod
    def __parse_extension_runtime_settings(plugin_settings_node, extension_runtime_settings_nodes, ext_handler):
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

            dependency_level = _ExtensionsGoalStateFromExtensionsConfig.__get_dependency_level_from_node(depends_on_node, extension_name)
            dependency_levels[extension_name] = dependency_level

        ext_handler.supports_multi_config = True
        for extension_runtime_setting_node in extension_runtime_settings_nodes:
            # Name and State will only be set for ExtensionRuntimeSettings for Multi-Config
            extension_name = getattrib(extension_runtime_setting_node, "name")
            if extension_name in (None, ""):
                raise ExtensionsConfigError("Extension Name not specified for ExtensionRuntimeSettings for MultiConfig!")
            # State can either be `ExtensionState.Enabled` (default) or `ExtensionState.Disabled`
            state = getattrib(extension_runtime_setting_node, "state")
            state = ustr(state.lower()) if state not in (None, "") else ExtensionState.Enabled
            _ExtensionsGoalStateFromExtensionsConfig.__parse_and_add_extension_settings(extension_runtime_setting_node, extension_name,
                                                                ext_handler, dependency_levels[extension_name],
                                                                state=state)

    @staticmethod
    def __parse_and_add_extension_settings(settings_node, name, ext_handler, depends_on_level, state=ExtensionState.Enabled):
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
            ext_handler.properties.extensions.append(
                Extension(name=name, sequenceNumber=seq_no, state=state, dependencyLevel=depends_on_level))
            return

        for plugin_settings_list in runtime_settings["runtimeSettings"]:
            handler_settings = plugin_settings_list["handlerSettings"]
            ext = Extension()
            # There is no "extension name" for single Handler Settings. Use HandlerName for those
            ext.name = name
            ext.state = state
            ext.sequenceNumber = seq_no
            ext.publicSettings = handler_settings.get("publicSettings")
            ext.protectedSettings = handler_settings.get("protectedSettings")
            ext.dependencyLevel = depends_on_level
            thumbprint = handler_settings.get("protectedSettingsCertThumbprint")
            ext.certificateThumbprint = thumbprint
            ext_handler.properties.extensions.append(ext)


class _ExtensionsGoalStateFromVmSettings(ExtensionsGoalState):
    def __init__(self, etag, json_text):
        super(_ExtensionsGoalStateFromVmSettings, self).__init__()
        self._id = etag
        self._text = json_text

        try:
            self._parse_vm_settings(json_text)
            self._do_common_validations()
        except Exception as e:
            raise VmSettingsError("Error parsing vmSettings (etag: {0}): {1}\n{2}".format(etag, format_exception(e), self.get_redacted_text()))

    def _parse_vm_settings(self, json_text):
        vm_settings = _CaseFoldedDict.from_dict(json.loads(json_text))
        self._parse_status_upload_blob(vm_settings)
        self._parse_required_features(vm_settings)
        # TODO: Parse all atttributes

    def _parse_status_upload_blob(self, vm_settings):
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

    def get_redacted_text(self):
        return re.sub(r'("protectedSettings"\s*:\s*)"[^"]+"', r'\1"*** REDACTED ***"', self._text)


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





