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
import os
import re
import time
import json

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.event import add_event, WALAEventOperation, LogEvent
from azurelinuxagent.common.exception import ProtocolError, ResourceGoneError
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.hostplugin import VmSettingsNotSupported, VmSettingsSupportStopped
from azurelinuxagent.common.protocol.restapi import RemoteAccessUser, RemoteAccessUsersList, ExtHandlerPackage, ExtHandlerPackageList
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.archive import GoalStateHistory, SHARED_CONF_FILE_NAME
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext
from azurelinuxagent.ga.signature_validation_util import signature_validation_enabled


GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PFX_FILE_NAME = "Certificates.pfx"
PEM_FILE_NAME = "Certificates.pem"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"

_GET_GOAL_STATE_MAX_ATTEMPTS = 6


class GoalStateProperties(object):
    """
    Enum for defining the properties that we fetch in the goal state
    """
    RoleConfig = 0x1
    HostingEnv = 0x2
    SharedConfig = 0x4
    ExtensionsGoalState = 0x8
    Certificates = 0x10
    RemoteAccessInfo = 0x20
    All = RoleConfig | HostingEnv | SharedConfig | ExtensionsGoalState | Certificates | RemoteAccessInfo


class GoalState(object):
    def __init__(self, wire_client, goal_state_properties=GoalStateProperties.All, silent=False, save_to_history=False):
        """
        Fetches the goal state using the given wire client.

        Fetching the goal state involves several HTTP requests to the WireServer and the HostGAPlugin. There is an initial request to WireServer's goalstate API,
        which response includes the incarnation, role instance, container ID, role config, and URIs to the rest of the goal state (ExtensionsConfig, Certificates,
        Remote Access users, etc.). Additional requests are done using those URIs (all of them point to APIs in the WireServer). Additionally, there is a
        request to the HostGAPlugin for the vmSettings, which determines the goal state for extensions when using the Fast Track pipeline.

        To reduce the number of requests, when possible, create a single instance of GoalState and use the update() method to keep it up to date.
        """
        try:
            self._wire_client = wire_client
            self._history = None
            self._save_to_history = save_to_history
            self._extensions_goal_state = None  # populated from vmSettings or extensionsConfig
            self._goal_state_properties = goal_state_properties
            self.logger = logger.Logger(logger.DEFAULT_LOGGER)
            self.logger.silent = silent

            # These properties hold the goal state from the WireServer and are initialized by self._fetch_full_wire_server_goal_state()
            self._incarnation = None
            self._role_instance_id = None
            self._role_config_name = None
            self._container_id = None
            self._hosting_env = None
            self._shared_conf = None
            self._certs = EmptyCertificates()
            self._certs_uri = None
            self._remote_access = None

            self.update(silent=silent)

        except ProtocolError:
            raise
        except Exception as exception:
            # We don't log the error here since fetching the goal state is done every few seconds
            raise ProtocolError(msg="Error fetching goal state", inner=exception)

    @property
    def incarnation(self):
        return self._incarnation

    @property
    def container_id(self):
        if not self._goal_state_properties & GoalStateProperties.RoleConfig:
            raise ProtocolError("ContainerId is not in goal state properties")
        else:
            return self._container_id

    @property
    def role_instance_id(self):
        if not self._goal_state_properties & GoalStateProperties.RoleConfig:
            raise ProtocolError("RoleInstanceId is not in goal state properties")
        else:
            return self._role_instance_id

    @property
    def role_config_name(self):
        if not self._goal_state_properties & GoalStateProperties.RoleConfig:
            raise ProtocolError("RoleConfig is not in goal state properties")
        else:
            return self._role_config_name

    @property
    def extensions_goal_state(self):
        if not self._goal_state_properties & GoalStateProperties.ExtensionsGoalState:
            raise ProtocolError("ExtensionsGoalState is not in goal state properties")
        else:
            return self._extensions_goal_state

    @property
    def certs(self):
        if not self._goal_state_properties & GoalStateProperties.Certificates:
            raise ProtocolError("Certificates is not in goal state properties")
        else:
            return self._certs

    @property
    def hosting_env(self):
        if not self._goal_state_properties & GoalStateProperties.HostingEnv:
            raise ProtocolError("HostingEnvironment is not in goal state properties")
        else:
            return self._hosting_env

    @property
    def shared_conf(self):
        if not self._goal_state_properties & GoalStateProperties.SharedConfig:
            raise ProtocolError("SharedConfig is not in goal state properties")
        else:
            return self._shared_conf

    @property
    def remote_access(self):
        if not self._goal_state_properties & GoalStateProperties.RemoteAccessInfo:
            raise ProtocolError("RemoteAccessInfo is not in goal state properties")
        else:
            return self._remote_access

    @property
    def history(self):
        return self._history

    def fetch_agent_manifest(self, family_name, uris):
        """
        This is a convenience method that wraps WireClient.fetch_manifest(), but adds the required 'use_verify_header' parameter and saves
        the manifest to the history folder.
        """
        return self._fetch_manifest("agent", "waagent.{0}".format(family_name), uris)

    def fetch_extension_manifest(self, extension_name, uris):
        """
        This is a convenience method that wraps WireClient.fetch_manifest(), but adds the required 'use_verify_header' parameter and saves
        the manifest to the history folder.
        """
        return self._fetch_manifest("extension", extension_name, uris)

    def _fetch_manifest(self, manifest_type, name, uris):
        try:
            is_fast_track = self.extensions_goal_state.source == GoalStateSource.FastTrack
            xml_text = self._wire_client.fetch_manifest(manifest_type, uris, use_verify_header=is_fast_track)
            if self._save_to_history:
                self._history.save_manifest(name, xml_text)
            return ExtensionManifest(xml_text)
        except Exception as e:
            raise ProtocolError("Failed to retrieve {0} manifest. Error: {1}".format(manifest_type, ustr(e)))

    @staticmethod
    def update_host_plugin_headers(wire_client):
        """
        Updates the container ID and role config name that are send in the headers of HTTP requests to the HostGAPlugin
        """
        # Fetching the goal state updates the HostGAPlugin so simply trigger the request
        GoalState._fetch_goal_state(wire_client)

    def update(self, force_update=False, silent=False):
        """
        Updates the current GoalState instance fetching values from the WireServer/HostGAPlugin as needed
        """
        self.logger.silent = silent

        #
        # Fetch the goal state from both the HGAP and the WireServer
        #
        timestamp = datetime.datetime.now(UTC)

        if force_update:
            message = "Refreshing goal state and vmSettings"
            self.logger.info(message)
            add_event(op=WALAEventOperation.GoalState, message=message)

        incarnation, xml_text, xml_doc = GoalState._fetch_goal_state(self._wire_client)
        goal_state_updated = force_update or incarnation != self._incarnation
        if goal_state_updated:
            message = 'Fetched a new incarnation for the WireServer goal state [incarnation {0}]'.format(incarnation)
            self.logger.info(message)
            add_event(op=WALAEventOperation.GoalState, message=message)

        vm_settings, vm_settings_updated = None, False
        if self._goal_state_properties & GoalStateProperties.ExtensionsGoalState:
            try:
                vm_settings, vm_settings_updated = GoalState._fetch_vm_settings(self._wire_client, force_update=force_update)
            except VmSettingsSupportStopped as exception:  # If the HGAP stopped supporting vmSettings, we need to use the goal state from the WireServer
                self._restore_wire_server_goal_state(incarnation, xml_text, xml_doc, exception)
                return

        if vm_settings_updated:
            self.logger.info('')
            message = "Fetched new vmSettings [HostGAPlugin correlation ID: {0} eTag: {1} source: {2}]".format(vm_settings.hostga_plugin_correlation_id, vm_settings.etag, vm_settings.source)
            self.logger.info(message)
            add_event(op=WALAEventOperation.GoalState, message=message)
        # Ignore the vmSettings if their source is Fabric (processing a Fabric goal state may require the tenant certificate and the vmSettings don't include it.)
        if vm_settings is not None and vm_settings.source == GoalStateSource.Fabric:
            if vm_settings_updated:
                message = "The vmSettings originated via Fabric; will ignore them."
                self.logger.info(message)
                add_event(op=WALAEventOperation.GoalState, message=message)
            vm_settings, vm_settings_updated = None, False

        # If neither goal state has changed we are done with the update
        if not goal_state_updated and not vm_settings_updated:
            return

        # Start a new history subdirectory and capture the updated goal state
        tag = "{0}".format(incarnation) if vm_settings is None else "{0}-{1}".format(incarnation, vm_settings.etag)
        if self._save_to_history:
            self._history = GoalStateHistory(timestamp, tag)
            if goal_state_updated:
                self._history.save_goal_state(xml_text)
            if vm_settings_updated:
                self._history.save_vm_settings(vm_settings.get_redacted_text())

        #
        # Continue fetching the rest of the goal state
        #
        extensions_config = None
        if goal_state_updated:
            extensions_config = self._fetch_full_wire_server_goal_state(incarnation, xml_doc)

        # Process only if extensions goal state was requested
        if self._goal_state_properties & GoalStateProperties.ExtensionsGoalState:
            #
            # Lastly, decide whether to use the vmSettings or extensionsConfig for the extensions goal state
            #
            if goal_state_updated:
                # On rotation of the tenant certificate the vmSettings and extensionsConfig are not updated. However, the incarnation of the WS goal state is update so 'goal_state_updated' will be True.
                # In this case, we should use the most recent of vmSettigns and extensionsConfig.
                if vm_settings is not None:
                    most_recent = vm_settings if vm_settings.created_on_timestamp > extensions_config.created_on_timestamp else extensions_config
                else:
                    most_recent = extensions_config
            else:  # vm_settings_updated
                most_recent = vm_settings

            if self._extensions_goal_state is None or most_recent.created_on_timestamp >= self._extensions_goal_state.created_on_timestamp:
                self._extensions_goal_state = most_recent

            # For each extension in the goal state being executed, we emit telemetry to indicate whether a signature is present
            # for the extension. The "is_success" field reflects whether the extension was signed.
            # Only send telemetry if the following conditions are met:
            #   - Goal state API supports 'encoded_signature' property (e.g., for fast track goal states, HGAP version should support signature)
            #   - Signature validation is enabled
            #   - Extension requested state is *not* 'uninstall' (uninstall goal states never include signature).
            #
            if signature_validation_enabled() and self._extensions_goal_state.supports_encoded_signature():
                for ext in self._extensions_goal_state.extensions:
                    if ext.state == "uninstall":
                        continue
                    msg = "Goal state {0} signature for extension package".format("contains" if ext.encoded_signature else "does not contain")
                    self.logger.info(msg)
                    add_event(op=WALAEventOperation.ExtensionSigned, message=msg, name=ext.name, version=ext.version, is_success=ext.encoded_signature != "", log_event=False)

            # Ensure all certificates are downloaded on Fast Track goal states in order to maintain backwards compatibility with previous
            # versions of the Agent, which used to download certificates from the WireServer on every goal state. Some customer applications
            # depend on this behavior (see https://github.com/Azure/WALinuxAgent/issues/2750).
            #
            if self._extensions_goal_state.source == GoalStateSource.FastTrack and self._goal_state_properties & GoalStateProperties.Certificates:
                self._check_and_download_missing_certs_on_disk()

    def _download_certificates(self, certs_uri):
        certs = Certificates(self._wire_client, certs_uri, self.logger)
        # Save the certificates summary (i.e. the thumbprints but not the certificates themselves) to the goal state history
        if self._save_to_history:
            self._history.save_certificates(json.dumps(certs.summary))
        return certs

    def _check_and_download_missing_certs_on_disk(self):
        # Re-download certificates if any have been removed from disk since last download
        if self._certs_uri is not None:
            certificates = self.certs.summary
            certs_missing_from_disk = False

            for c in certificates:
                cert_path = os.path.join(conf.get_lib_dir(), c['thumbprint'] + '.crt')
                if not os.path.isfile(cert_path):
                    certs_missing_from_disk = True
                    message = "Certificate required by goal state is not on disk: {0}".format(cert_path)
                    self.logger.info(message)
                    add_event(op=WALAEventOperation.GoalState, message=message)
            if certs_missing_from_disk:
                # Try to re-download certs. Sometimes download may fail if certs_uri is outdated/contains wrong
                # container id (for example, when the VM is moved to a new container after resuming from
                # hibernation). If download fails we should report and continue with goal state processing, as some
                # extensions in the goal state may succeed.
                try:
                    self._download_certificates(self._certs_uri)
                except Exception as e:
                    message = "Unable to download certificates. Goal state processing will continue, some " \
                              "extensions requiring certificates may fail. Error: {0}".format(ustr(e))
                    self.logger.warn(message)
                    add_event(op=WALAEventOperation.GoalState, is_success=False, message=message)

    def _restore_wire_server_goal_state(self, incarnation, xml_text, xml_doc, vm_settings_support_stopped_error):
        msg = 'The HGAP stopped supporting vmSettings; will fetched the goal state from the WireServer.'
        self.logger.info(msg)
        add_event(op=WALAEventOperation.VmSettings, message=msg)
        if self._save_to_history:
            self._history = GoalStateHistory(datetime.datetime.now(UTC), incarnation)
            self._history.save_goal_state(xml_text)
        self._extensions_goal_state = self._fetch_full_wire_server_goal_state(incarnation, xml_doc)
        if self._extensions_goal_state.created_on_timestamp < vm_settings_support_stopped_error.timestamp:
            self._extensions_goal_state.is_outdated = True
            msg = "Fetched a Fabric goal state older than the most recent FastTrack goal state; will skip it.\nFabric:    {0}\nFastTrack: {1}".format(
                  self._extensions_goal_state.created_on_timestamp, vm_settings_support_stopped_error.timestamp)
            self.logger.info(msg)
            add_event(op=WALAEventOperation.VmSettings, message=msg)

    def save_to_history(self, data, file_name):
        if self._save_to_history:
            self._history.save(data, file_name)

    @staticmethod
    def _fetch_goal_state(wire_client):
        """
        Issues an HTTP request for the goal state (WireServer) and returns a tuple containing the response as text and as an XML Document
        """
        uri = GOAL_STATE_URI.format(wire_client.get_endpoint())

        # In some environments a few goal state requests return a missing RoleInstance; these retries are used to work around that issue
        # TODO: Consider retrying on 410 (ResourceGone) as well
        incarnation = "unknown"
        for _ in range(0, _GET_GOAL_STATE_MAX_ATTEMPTS):
            xml_text = wire_client.fetch_config(uri, wire_client.get_header())
            xml_doc = parse_doc(xml_text)
            incarnation = findtext(xml_doc, "Incarnation")

            role_instance = find(xml_doc, "RoleInstance")
            if role_instance:
                break
            time.sleep(0.5)
        else:
            raise ProtocolError("Fetched goal state without a RoleInstance [incarnation {inc}]".format(inc=incarnation))

        # Telemetry and the HostGAPlugin depend on the container id/role config; keep them up-to-date each time we fetch the goal state
        # (note that these elements can change even if the incarnation of the goal state does not change)
        container = find(xml_doc, "Container")
        container_id = findtext(container, "ContainerId")
        role_config = find(role_instance, "Configuration")
        role_config_name = findtext(role_config, "ConfigName")

        AgentGlobals.update_container_id(container_id)  # Telemetry uses this global to pick up the container id

        wire_client.update_host_plugin(container_id, role_config_name)

        return incarnation, xml_text, xml_doc

    @staticmethod
    def _fetch_vm_settings(wire_client, force_update=False):
        """
        Issues an HTTP request (HostGAPlugin) for the vm settings and returns the response as an ExtensionsGoalState.
        """
        vm_settings, vm_settings_updated = (None, False)

        if conf.get_enable_fast_track():
            try:
                try:
                    vm_settings, vm_settings_updated = wire_client.get_host_plugin().fetch_vm_settings(force_update=force_update)
                except ResourceGoneError:
                    # retry after refreshing the HostGAPlugin
                    GoalState.update_host_plugin_headers(wire_client)
                    vm_settings, vm_settings_updated = wire_client.get_host_plugin().fetch_vm_settings(force_update=force_update)

            except VmSettingsSupportStopped:
                raise
            except VmSettingsNotSupported:
                pass
            except VmSettingsParseError as exception:
                # ensure we save the vmSettings if there were parsing errors, but save them only once per ETag
                if not GoalStateHistory.tag_exists(exception.etag):
                    GoalStateHistory(datetime.datetime.now(UTC), exception.etag).save_vm_settings(exception.vm_settings_text)
                raise

        return vm_settings, vm_settings_updated

    def _fetch_full_wire_server_goal_state(self, incarnation, xml_doc):
        """
        Issues HTTP requests (to the WireServer) for each of the URIs in the goal state (ExtensionsConfig, Certificate, Remote Access users, etc)
        and populates the corresponding properties.

        Returns the value of ExtensionsConfig.
        """
        try:
            self.logger.info('')
            message = 'Fetching full goal state from the WireServer [incarnation {0}]'.format(incarnation)
            self.logger.info(message)
            add_event(op=WALAEventOperation.GoalState, message=message)

            role_instance_id = None
            role_config_name = None
            container_id = None
            if GoalStateProperties.RoleConfig & self._goal_state_properties:
                role_instance = find(xml_doc, "RoleInstance")
                role_instance_id = findtext(role_instance, "InstanceId")
                role_config = find(role_instance, "Configuration")
                role_config_name = findtext(role_config, "ConfigName")
                container = find(xml_doc, "Container")
                container_id = findtext(container, "ContainerId")

            extensions_config_uri = findtext(xml_doc, "ExtensionsConfig")
            if not (GoalStateProperties.ExtensionsGoalState & self._goal_state_properties) or extensions_config_uri is None:
                extensions_config = ExtensionsGoalStateFactory.create_empty(incarnation)
            else:
                xml_text = self._wire_client.fetch_config(extensions_config_uri, self._wire_client.get_header())
                extensions_config = ExtensionsGoalStateFactory.create_from_extensions_config(incarnation, xml_text, self._wire_client)
                if self._save_to_history:
                    self._history.save_extensions_config(extensions_config.get_redacted_text())

            hosting_env = None
            if GoalStateProperties.HostingEnv & self._goal_state_properties:
                hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
                xml_text = self._wire_client.fetch_config(hosting_env_uri, self._wire_client.get_header())
                hosting_env = HostingEnv(xml_text)
                if self._save_to_history:
                    self._history.save_hosting_env(xml_text)

            shared_config = None
            if GoalStateProperties.SharedConfig & self._goal_state_properties:
                shared_conf_uri = findtext(xml_doc, "SharedConfig")
                xml_text = self._wire_client.fetch_config(shared_conf_uri, self._wire_client.get_header())
                shared_config = SharedConfig(xml_text)
                if self._save_to_history:
                    self._history.save_shared_conf(xml_text)
                # SharedConfig.xml is used by other components (Azsec and Singularity/HPC Infiniband), so save it to the agent's root directory as well
                shared_config_file = os.path.join(conf.get_lib_dir(), SHARED_CONF_FILE_NAME)
                try:
                    fileutil.write_file(shared_config_file, xml_text)
                except Exception as e:
                    logger.warn("Failed to save {0}: {1}".format(shared_config, e))

            certs = EmptyCertificates()
            certs_uri = findtext(xml_doc, "Certificates")
            if (GoalStateProperties.Certificates & self._goal_state_properties) and certs_uri is not None:
                certs = self._download_certificates(certs_uri)

            remote_access = None
            if GoalStateProperties.RemoteAccessInfo & self._goal_state_properties:
                remote_access_uri = findtext(container, "RemoteAccessInfo")
                if remote_access_uri is not None:
                    xml_text = self._wire_client.fetch_config(remote_access_uri, self._wire_client.get_header_for_remote_access())
                    remote_access = RemoteAccess(xml_text)
                    if self._save_to_history:
                        self._history.save_remote_access(xml_text)

            self._incarnation = incarnation
            self._role_instance_id = role_instance_id
            self._role_config_name = role_config_name
            self._container_id = container_id
            self._hosting_env = hosting_env
            self._shared_conf = shared_config
            self._certs = certs
            self._certs_uri = certs_uri
            self._remote_access = remote_access

            return extensions_config

        except Exception as exception:
            self.logger.warn("Fetching the goal state failed: {0}", ustr(exception))
            raise ProtocolError(msg="Error fetching goal state", inner=exception)
        finally:
            message = 'Fetch goal state from WireServer completed'
            self.logger.info(message)
            add_event(op=WALAEventOperation.GoalState, message=message)


class HostingEnv(object):
    def __init__(self, xml_text):
        self.xml_text = xml_text
        xml_doc = parse_doc(xml_text)
        incarnation = find(xml_doc, "Incarnation")
        self.vm_name = getattrib(incarnation, "instance")
        role = find(xml_doc, "Role")
        self.role_name = getattrib(role, "name")
        deployment = find(xml_doc, "Deployment")
        self.deployment_name = getattrib(deployment, "name")


class SharedConfig(object):
    def __init__(self, xml_text):
        self.xml_text = xml_text


class Certificates(LogEvent):
    def __init__(self, wire_client, uri, logger_):
        super(Certificates, self).__init__(logger_)
        self.summary = []
        self._crypt_util = CryptUtil(conf.get_openssl_cmd())

        pfx_file = os.path.join(conf.get_lib_dir(), PFX_FILE_NAME)
        pem_file = os.path.join(conf.get_lib_dir(), PEM_FILE_NAME)

        create_empty_pem_file = False

        try:
            if not self._try_download_certificates_pfx(wire_client, uri, pfx_file):
                create_empty_pem_file = True
                return  # The response from the WireServer did not have any certificates, or they were not in the expected format
            self._convert_certificates_pfx_to_pem(pfx_file, pem_file)
        except Exception as e:
            # A failure to download the certificates won't necessarily produce an error. Certificates do not change often and they may have
            # already been saved to disk on a previous goal state. We simply report the error and continue processing the goal_state; later on,
            # before extensions are processed, the Agent checks whether the required certificates are already on disk and refreshes the goal
            # state if they are not.
            self.error(WALAEventOperation.GoalStateCertificates, "Error fetching the goal state certificates: {0}", ustr(e))
            create_empty_pem_file = True
            return
        finally:
            if create_empty_pem_file:
                # Agents older than 2.13.1.1 can go into an infinite loop during initialization of the Daemon if the certificates cannot
                # be downloaded/decrypted and the PEM file does not exist. Create an empty file (or overwrite any existing file from previous
                # goal states) to ensure it exists.
                open(pem_file, "w").close()
            self._remove_file(pfx_file)

        try:
            self.summary = self._extract_certificate(pem_file)
        except Exception as e:
            self.error(WALAEventOperation.GoalStateCertificates, "Error extracting the goal state certificates from {0}: {1}", pem_file, ustr(e))

        for c in self.summary:
            self.info(WALAEventOperation.GoalStateCertificates, "Downloaded certificate {0}", c)

    def _remove_file(self, file):
        if os.path.exists(file):
            try:
                os.remove(file)
            except Exception as e:
                self.warn(WALAEventOperation.GoalStateCertificates, "Failed to remove {0}: {1}", file, ustr(e))

    def _try_download_certificates_pfx(self, wire_client, uri, pfx_file):
        """
        Downloads the certificates from the WireServer and saves them to the given pfx file path.
        Returns True if the certificates were downloaded, False if the WireServer response does not have a "Data" element, or if the certificates are not in the expected format.
        """
        trans_prv_file = os.path.join(conf.get_lib_dir(), TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(), TRANSPORT_CERT_FILE_NAME)
        xml_file = os.path.join(conf.get_lib_dir(), CERTS_FILE_NAME)

        for cypher in ["AES128_CBC", "DES_EDE3_CBC"]:
            headers = wire_client.get_headers_for_encrypted_request(cypher)

            try:
                xml_text = wire_client.fetch_config(uri, headers)
            except Exception as e:
                self.warn(WALAEventOperation.GoalStateCertificates, "Error in Certificates request [cypher: {0}]: {1}", cypher, ustr(e))
                continue

            fileutil.write_file(xml_file, xml_text)

            xml_doc = parse_doc(xml_text)
            data = findtext(xml_doc, "Data")
            if data is None:
                self.info(WALAEventOperation.GoalStateCertificates, "The Data element of the Certificates response is empty")
                return False
            certificate_format = findtext(xml_doc, "Format")
            if certificate_format and certificate_format != "Pkcs7BlobWithPfxContents":
                self.warn(WALAEventOperation.GoalStateCertificates, "The Certificates format is not Pkcs7BlobWithPfxContents; skipping. Format is {0}", certificate_format)
                return False

            p7m_file = Certificates._create_p7m_file(data)

            try:
                self._crypt_util.decrypt_certificates_p7m(p7m_file, trans_prv_file, trans_cert_file, pfx_file)
            except shellutil.CommandError as e:
                self.warn(WALAEventOperation.GoalState, "Error in transport decryption [cypher: {0}]: {1}", cypher, ustr(e))
                self._remove_file(pfx_file)
                continue

            return True

        raise Exception("Cannot download certificates using any of the supported cyphers")

    @staticmethod
    def _create_p7m_file(data):
        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n"  # pylint: disable=W1308
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(p7m_file, p7m_file, data)
        fileutil.write_file(p7m_file, p7m)
        return p7m_file

    def _convert_certificates_pfx_to_pem(self, pfx_file, pem_file):
        """
        Convert the pfx file to PEM and saves the result to the given file.
        """
        for nomacver in [True, False]:
            try:
                self._crypt_util.convert_pfx_to_pem(pfx_file, nomacver, pem_file)
                return pem_file
            except shellutil.CommandError as e:
                self.warn(WALAEventOperation.GoalState, "Error converting PFX to PEM [-nomacver: {0}]: {1}", nomacver, ustr(e))
                continue

        raise Exception("Cannot convert PFX to PEM")

    def _extract_certificate(self, pem_file):
        """
        Parse the certificates and private keys from the pem file and store them in the certificates directory.
        """
        # The parsing process use public key to match prv and crt.
        private_keys = {}  # map of private keys indexed by public key
        thumbprints = {}  # map of thumbprints indexed by public key
        buffer = []  # buffer for reading lines belonging to a certificate or private key
        index = 0

        with open(pem_file) as pem:
            for line in pem.readlines():
                buffer.append(line)
                if re.match(r'[-]+END.*KEY[-]+', line):
                    tmp_file = Certificates._write_to_tmp_file(index, 'prv', buffer)
                    pub = self._crypt_util.get_pubkey_from_prv(tmp_file)
                    private_keys[pub] = tmp_file
                    buffer = []
                    index += 1
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmp_file = Certificates._write_to_tmp_file(index, 'crt', buffer)
                    pub = self._crypt_util.get_pubkey_from_crt(tmp_file)
                    thumbprint = self._crypt_util.get_thumbprint_from_crt(tmp_file)
                    thumbprints[pub] = thumbprint
                    # Rename crt with thumbprint as the file name
                    crt = "{0}.crt".format(thumbprint)
                    os.rename(tmp_file, os.path.join(conf.get_lib_dir(), crt))
                    buffer = []
                    index += 1

        # Rename prv key with thumbprint as the file name
        for pubkey in private_keys:
            thumbprint = thumbprints[pubkey]
            if thumbprint:
                tmp_file = private_keys[pubkey]
                prv = "{0}.prv".format(thumbprint)
                os.rename(tmp_file, os.path.join(conf.get_lib_dir(), prv))
            else:
                # Since private key has *no* matching certificate, it will not be named correctly
                self.warn(WALAEventOperation.GoalState, "Found a private key with no matching cert/thumbprint!")

        certificates = []
        for pubkey, thumbprint in thumbprints.items():
            has_private_key = pubkey in private_keys
            certificates.append({"thumbprint": thumbprint, "hasPrivateKey": has_private_key})
        return certificates

    @staticmethod
    def _write_to_tmp_file(index, suffix, buf):
        file_name = os.path.join(conf.get_lib_dir(), "{0}.{1}".format(index, suffix))
        fileutil.write_file(file_name, "".join(buf))
        return file_name

class EmptyCertificates:
    def __init__(self):
        self.summary = []

class RemoteAccess(object):
    """
    Object containing information about user accounts
    """
    #
    # <RemoteAccess>
    #   <Version/>
    #   <Incarnation/>
    #    <Users>
    #       <User>
    #         <Name/>
    #         <Password/>
    #         <Expiration/>
    #       </User>
    #     </Users>
    #   </RemoteAccess>
    #
    def __init__(self, xml_text):
        self.xml_text = xml_text
        self.version = None
        self.incarnation = None
        self.user_list = RemoteAccessUsersList()

        if self.xml_text is None or len(self.xml_text) == 0:
            return

        xml_doc = parse_doc(self.xml_text)
        self.version = findtext(xml_doc, "Version")
        self.incarnation = findtext(xml_doc, "Incarnation")
        user_collection = find(xml_doc, "Users")
        users = findall(user_collection, "User")

        for user in users:
            remote_access_user = RemoteAccess._parse_user(user)
            self.user_list.users.append(remote_access_user)

    @staticmethod
    def _parse_user(user):
        name = findtext(user, "Name")
        encrypted_password = findtext(user, "Password")
        expiration = findtext(user, "Expiration")
        remote_access_user = RemoteAccessUser(name, encrypted_password, expiration)
        return remote_access_user


class ExtensionManifest(object):
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ExtensionManifest is None")
        logger.verbose("Load ExtensionManifest.xml")
        self.pkg_list = ExtHandlerPackageList()
        self._parse(xml_text)

    def _parse(self, xml_text):
        xml_doc = parse_doc(xml_text)
        self._handle_packages(findall(find(xml_doc,
                                           "Plugins"),
                                      "Plugin"),
                              False)
        self._handle_packages(findall(find(xml_doc,
                                           "InternalPlugins"),
                                      "Plugin"),
                              True)

    def _handle_packages(self, packages, isinternal):
        for package in packages:
            version = findtext(package, "Version")

            disallow_major_upgrade = findtext(package,
                                              "DisallowMajorVersionUpgrade")
            if disallow_major_upgrade is None:
                disallow_major_upgrade = ''
            disallow_major_upgrade = disallow_major_upgrade.lower() == "true"

            uris = find(package, "Uris")
            uri_list = findall(uris, "Uri")
            uri_list = [gettext(x) for x in uri_list]
            pkg = ExtHandlerPackage()
            pkg.version = version
            pkg.disallow_major_upgrade = disallow_major_upgrade
            for uri in uri_list:
                pkg.uris.append(uri)

            pkg.isinternal = isinternal
            self.pkg_list.versions.append(pkg)


