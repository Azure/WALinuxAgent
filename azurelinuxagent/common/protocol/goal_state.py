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
import os
import re
import traceback

from azurelinuxagent.common.exception import ProtocolError

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.datacontract import set_properties
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import Cert, CertList, Extension, ExtHandler, ExtHandlerList, \
    ExtHandlerVersionUri, RemoteAccessUser, RemoteAccessUsersList, \
    VMAgentManifest, VMAgentManifestList, VMAgentManifestUri
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext
from azurelinuxagent.common.version import AGENT_NAME

GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PEM_FILE_NAME = "Certificates.pem"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"


# Type of update performed by _update_from_goal_state()
class UpdateType(object):
    # Update the Host GA Plugin client (Container ID and RoleConfigName)
    HostPlugin = 0
    # Update the full goal state only if the incarnation has changed
    GoalState = 1
    # Update the full goal state unconditionally
    GoalStateForced = 2


class GoalState(object): # pylint: disable=R0902
    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    ContainerID = "00000000-0000-0000-0000-000000000000"
    _HttpFailedIndicator = "[HTTP Failed]"

    def __init__(self, wire_client, retrieval_mode):
        """
        Fetches the goal state using the given wire client.

        For better code readability, use the static fetch_* methods below instead of instantiating GoalState
        directly.

        """
        uri = GOAL_STATE_URI.format(wire_client.get_endpoint())
        self.xml_text = wire_client.fetch_config(uri, wire_client.get_header())
        xml_doc = parse_doc(self.xml_text)

        self.ext_conf = None
        self.hosting_env = None
        self.shared_conf = None
        self.certs = None
        self.remote_access = None

        # Retrieve goal state information
        self.incarnation = findtext(xml_doc, "Incarnation")
        role_instance = find(xml_doc, "RoleInstance")
        self.role_instance_id = findtext(role_instance, "InstanceId")
        role_config = find(role_instance, "Configuration")
        self.role_config_name = findtext(role_config, "ConfigName")
        container = find(xml_doc, "Container")
        self.container_id = findtext(container, "ContainerId")
        lbprobe_ports = find(xml_doc, "LBProbePorts")
        self.load_balancer_probe_port = findtext(lbprobe_ports, "Port")
        AgentGlobals.update_container_id(self.container_id)

        if retrieval_mode != UpdateType.HostPlugin:
            # Retrieve the extension config, which we need to determine if anything changed
            self._retrieve_ext_conf(xml_doc, wire_client)

            if self.ext_conf is not None or retrieval_mode == UpdateType.GoalStateForced:
                # We only need to retrieve the certificates if there's a Fabric incarnation change.
                # FastTrack doesn't affect them
                if self.ext_conf.is_fabric_change or retrieval_mode == UpdateType.GoalStateForced:
                    self._retrieve_certificates(xml_doc, wire_client)

                # Retrieve the other documents if we have either a Fabric or FastTrack change
                if self.ext_conf.changed or retrieval_mode == UpdateType.GoalStateForced:
                    self._retrieve_hosting_env(xml_doc, wire_client)
                    self._retrieve_shared_conf(xml_doc, wire_client)
                    self._retrieve_remote_access(xml_doc, wire_client)
                    self._retrieve_remote_access(xml_doc, wire_client)

    @staticmethod
    def fetch_goal_state(wire_client):
        """
        Fetches the goal state. If it has changed, it fetches the full goal state
        Otherwise it fetches the goal state not including any nested properties (such as remote access).
        """
        return GoalState(wire_client, retrieval_mode=UpdateType.GoalState)

    @staticmethod
    def fetch_limited_goal_state(wire_client):
        """
        Fetches only the wire server GoalState object. Does not include the extensions config
        """
        return GoalState(wire_client, retrieval_mode=UpdateType.HostPlugin)

    @staticmethod
    def fetch_full_goal_state(wire_client):
        """
        Fetches the full goal state, including nested properties (such as remote access).
        """
        return GoalState(wire_client, retrieval_mode=UpdateType.GoalStateForced)

    def _retrieve_hosting_env(self, xml_doc, wire_client):
        try:
            uri = findtext(xml_doc, "HostingEnvironmentConfig")
            if uri is None:
                logger.error("HostingEnvironmentConfig url doesn't exist in goal state")
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header())
                self.hosting_env = HostingEnv(xml_text)
        except Exception as e:
            self._log_document_retrieval_failure("hosting environment", e)
            raise

    def _retrieve_certificates(self, xml_doc, wire_client):
        try:
            uri = findtext(xml_doc, "Certificates")
            if uri is not None:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header_for_cert())
                self.certs = Certificates(xml_text)
        except Exception as e:
            self._log_document_retrieval_failure("certificates", e)
            raise

    def _retrieve_shared_conf(self, xml_doc, wire_client):
        try:
            uri = findtext(xml_doc, "SharedConfig")
            if uri is None:
                logger.error("SharedConfig url doesn't exist in goal state")
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header())
                self.shared_conf = SharedConfig(xml_text)
        except Exception as e:
            self._log_document_retrieval_failure("shared config", e)
            raise

    def _retrieve_remote_access(self, xml_doc, wire_client):
        try:
            container = find(xml_doc, "Container")
            uri = findtext(container, "RemoteAccessInfo")
            if uri is None:
                self.remote_access = None
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header_for_cert())
                self.remote_access = RemoteAccess(xml_text)
        except Exception as e: # pylint: disable=C0103
            self._log_document_retrieval_failure("remove access", e)
            raise

    def _retrieve_ext_conf(self, xml_doc, wire_client):
        try:
            uri = findtext(xml_doc, "ExtensionsConfig")
            self.ext_conf = wire_client.ext_config_retriever.get_ext_config(self.incarnation, uri)
        except Exception as e:
            self._log_document_retrieval_failure("extensions config", e)
            raise

    def _log_document_retrieval_failure(self, component_name, e):
        if isinstance(ProtocolError, e):
            logger.warn("Fetching the {0} failed: {1}", component_name, ustr(e))
        else:
            logger.warn("Fetching the {0} failed: {1}, {2}", component_name, ustr(e), traceback.format_exc())


class HostingEnv(object): # pylint: disable=R0903
    def __init__(self, xml_text):
        self.xml_text = xml_text
        xml_doc = parse_doc(xml_text)
        incarnation = find(xml_doc, "Incarnation")
        self.vm_name = getattrib(incarnation, "instance")
        role = find(xml_doc, "Role")
        self.role_name = getattrib(role, "name")
        deployment = find(xml_doc, "Deployment")
        self.deployment_name = getattrib(deployment, "name")


class SharedConfig(object): # pylint: disable=R0903
    def __init__(self, xml_text):
        self.xml_text = xml_text


class Certificates(object): # pylint: disable=R0903
    def __init__(self, xml_text): # pylint: disable=R0912,R0914
        self.cert_list = CertList()

        # Save the certificates
        local_file = os.path.join(conf.get_lib_dir(), CERTS_FILE_NAME)
        fileutil.write_file(local_file, xml_text)

        # Separate the certificates into individual files.
        xml_doc = parse_doc(xml_text)
        data = findtext(xml_doc, "Data")
        if data is None:
            return

        # if the certificates format is not Pkcs7BlobWithPfxContents do not parse it
        certificateFormat = findtext(xml_doc, "Format") # pylint: disable=C0103
        if certificateFormat and certificateFormat != "Pkcs7BlobWithPfxContents":
            logger.warn("The Format is not Pkcs7BlobWithPfxContents. Format is " + certificateFormat)
            return

        cryptutil = CryptUtil(conf.get_openssl_cmd())
        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n" # pylint: disable=W1308
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(p7m_file, p7m_file, data)

        fileutil.write_file(p7m_file, p7m)

        trans_prv_file = os.path.join(conf.get_lib_dir(), TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(), TRANSPORT_CERT_FILE_NAME)
        pem_file = os.path.join(conf.get_lib_dir(), PEM_FILE_NAME)
        # decrypt certificates
        cryptutil.decrypt_p7m(p7m_file, trans_prv_file, trans_cert_file, pem_file)

        # The parsing process use public key to match prv and crt.
        buf = []
        begin_crt = False # pylint: disable=W0612
        begin_prv = False # pylint: disable=W0612
        prvs = {}
        thumbprints = {}
        index = 0
        v1_cert_list = []
        with open(pem_file) as pem:
            for line in pem.readlines():
                buf.append(line)
                if re.match(r'[-]+BEGIN.*KEY[-]+', line):
                    begin_prv = True
                elif re.match(r'[-]+BEGIN.*CERTIFICATE[-]+', line):
                    begin_crt = True
                elif re.match(r'[-]+END.*KEY[-]+', line):
                    tmp_file = Certificates._write_to_tmp_file(index, 'prv', buf)
                    pub = cryptutil.get_pubkey_from_prv(tmp_file)
                    prvs[pub] = tmp_file
                    buf = []
                    index += 1
                    begin_prv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmp_file = Certificates._write_to_tmp_file(index, 'crt', buf)
                    pub = cryptutil.get_pubkey_from_crt(tmp_file)
                    thumbprint = cryptutil.get_thumbprint_from_crt(tmp_file)
                    thumbprints[pub] = thumbprint
                    # Rename crt with thumbprint as the file name
                    crt = "{0}.crt".format(thumbprint)
                    v1_cert_list.append({
                        "name": None,
                        "thumbprint": thumbprint
                    })
                    os.rename(tmp_file, os.path.join(conf.get_lib_dir(), crt))
                    buf = []
                    index += 1
                    begin_crt = False

        # Rename prv key with thumbprint as the file name
        for pubkey in prvs:
            thumbprint = thumbprints[pubkey]
            if thumbprint:
                tmp_file = prvs[pubkey]
                prv = "{0}.prv".format(thumbprint)
                os.rename(tmp_file, os.path.join(conf.get_lib_dir(), prv))
                logger.info("Found private key matching thumbprint {0}".format(thumbprint))
            else:
                # Since private key has *no* matching certificate,
                # it will not be named correctly
                logger.warn("Found NO matching cert/thumbprint for private key!")

        # Log if any certificates were found without matching private keys
        # This can happen (rarely), and is useful to know for debugging
        for pubkey in thumbprints:
            if not pubkey in prvs:
                msg = "Certificate with thumbprint {0} has no matching private key."
                logger.info(msg.format(thumbprints[pubkey]))

        for v1_cert in v1_cert_list:
            cert = Cert()
            set_properties("certs", cert, v1_cert)
            self.cert_list.certificates.append(cert)

    @staticmethod
    def _write_to_tmp_file(index, suffix, buf):
        file_name = os.path.join(conf.get_lib_dir(), "{0}.{1}".format(index, suffix))
        fileutil.write_file(file_name, "".join(buf))
        return file_name


class ExtensionsConfig(object): # pylint: disable=R0903
    def __init__(self, xml_text): # pylint: disable=R0914
        self.xml_text = xml_text
        self.ext_handlers = ExtHandlerList()
        self.vmagent_manifests = VMAgentManifestList()
        self.svd_seqNo = None
        self.created_on_ticks = None

        if xml_text is None:
            return

        xml_doc = parse_doc(self.xml_text)

        self.status_upload_blob_url = findtext(xml_doc, "StatusUploadBlob")
        self.artifacts_profile_blob_url = findtext(xml_doc, "InVMArtifactsProfileBlob")

        status_upload_node = find(xml_doc, "StatusUploadBlob")
        self.status_upload_blob_type = getattrib(status_upload_node, "statusBlobType")
        logger.verbose("Extension config shows status blob type as [{0}]", self.status_upload_blob_type)

        ga_families_list = find(xml_doc, "GAFamilies")
        ga_families = findall(ga_families_list, "GAFamily")

        for ga_family in ga_families:
            family = findtext(ga_family, "Name")
            uris_list = find(ga_family, "Uris")
            uris = findall(uris_list, "Uri")
            manifest = VMAgentManifest()
            manifest.family = family
            for uri in uris:
                manifestUri = VMAgentManifestUri(uri=gettext(uri)) # pylint: disable=C0103
                manifest.versionsManifestUris.append(manifestUri)
            self.vmagent_manifests.vmAgentManifests.append(manifest)

        plugins_list = find(xml_doc, "Plugins")
        plugins = findall(plugins_list, "Plugin")
        plugin_settings_list = find(xml_doc, "PluginSettings")
        plugin_settings = findall(plugin_settings_list, "Plugin")

        for plugin in plugins:
            ext_handler = ExtensionsConfig._parse_plugin(plugin)
            self.ext_handlers.extHandlers.append(ext_handler)
            ExtensionsConfig._parse_plugin_settings(ext_handler, plugin_settings)

        goal_state_metadata_node = find(xml_doc, "InVMGoalStateMetaData")
        if goal_state_metadata_node is not None:
            self.svd_seqNo = getattrib(goal_state_metadata_node, "inSvdSeqNo")
            self.created_on_ticks = getattrib(goal_state_metadata_node, "createdOnTicks")
            logger.verbose("Read inSvdSeqNo of {0} and createdOnTicks of {1}", self.svd_seqNo, self.created_on_ticks)

    @staticmethod
    def _parse_plugin(plugin):
        ext_handler = ExtHandler()
        ext_handler.name = getattrib(plugin, "name")
        ext_handler.properties.version = getattrib(plugin, "version")
        ext_handler.properties.state = getattrib(plugin, "state")

        location = getattrib(plugin, "location")
        failover_location = getattrib(plugin, "failoverlocation")
        for uri in [location, failover_location]:
            version_uri = ExtHandlerVersionUri()
            version_uri.uri = uri
            ext_handler.versionUris.append(version_uri)
        return ext_handler

    @staticmethod
    def _parse_plugin_settings(ext_handler, plugin_settings): # pylint: disable=R0914
        if plugin_settings is None:
            return

        name = ext_handler.name
        version = ext_handler.properties.version

        ext_handler_plugin_settings = [x for x in plugin_settings if getattrib(x, "name") == name]
        if ext_handler_plugin_settings is None or len(ext_handler_plugin_settings) == 0: # pylint: disable=len-as-condition
            return

        settings = [x for x in ext_handler_plugin_settings if getattrib(x, "version") == version]
        if len(settings) != len(ext_handler_plugin_settings):
            msg = "ExtHandler PluginSettings Version Mismatch! Expected PluginSettings version: {0} for Handler: " \
                  "{1} but found versions: ({2})".format(version, name, ', '.join(
                set([getattrib(x, "version") for x in ext_handler_plugin_settings]))) 
            add_event(AGENT_NAME, op=WALAEventOperation.PluginSettingsVersionMismatch, message=msg, log_event=False,
                      is_success=False)
            if len(settings) == 0: # pylint: disable=len-as-condition
                # If there is no corresponding settings for the specific extension handler, we will not process it at all,
                # this is an unexpected error as we always expect both versions to be in sync.
                logger.error(msg)
                return
            logger.warn(msg)

        runtime_settings = None
        runtime_settings_node = find(settings[0], "RuntimeSettings")
        seqNo = getattrib(runtime_settings_node, "seqNo") # pylint: disable=C0103
        runtime_settings_str = gettext(runtime_settings_node)
        if runtime_settings_str is not None:
            try:
                runtime_settings = json.loads(runtime_settings_str)
            except ValueError as e: # pylint: disable=W0612,C0103
                logger.error("Invalid extension settings")
                return

        depends_on_level = 0
        depends_on_node = find(settings[0], "DependsOn")
        if depends_on_node is not None:
            try:
                depends_on_level = int(getattrib(depends_on_node, "dependencyLevel"))
            except (ValueError, TypeError):
                logger.warn("Could not parse dependencyLevel for handler {0}. Setting it to 0".format(name))
                depends_on_level = 0

        if runtime_settings is not None:
            for plugin_settings_list in runtime_settings["runtimeSettings"]:
                handler_settings = plugin_settings_list["handlerSettings"]
                ext = Extension()
                # There is no "extension name" in wire protocol.
                # Put
                ext.name = ext_handler.name
                ext.sequenceNumber = seqNo
                ext.publicSettings = handler_settings.get("publicSettings")
                ext.protectedSettings = handler_settings.get("protectedSettings")
                ext.dependencyLevel = depends_on_level
                thumbprint = handler_settings.get(
                    "protectedSettingsCertThumbprint")
                ext.certificateThumbprint = thumbprint
                ext_handler.properties.extensions.append(ext)


class RemoteAccess(object): # pylint: disable=R0903
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

        if self.xml_text is None or len(self.xml_text) == 0: # pylint: disable=len-as-condition
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

