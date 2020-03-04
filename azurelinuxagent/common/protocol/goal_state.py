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

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.datacontract import set_properties, DataContract, DataContractList
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext
from azurelinuxagent.common.protocol.restapi import *

GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PEM_FILE_NAME = "Certificates.pem"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"


class GoalState(object):
    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    ContainerID = "00000000-0000-0000-0000-000000000000"

    def __init__(self, wire_client, full_goal_state=False, base_incarnation=None):
        """
        Fetches the goal state using the given wire client.

        By default it fetches only the goal state itself; to fetch the entire goal state (that includes all the
        nested components, such as the extension config) use the 'full_goal_state' parameter.

        If 'base_incarnation' is given, it fetches the full goal state if the new incarnation is different than
        the given value, otherwise it fetches only the goal state itself.

        For better code readability, use the static fetch_* methods below instead of instantiating GoalState
        directly.

        """
        uri = GOAL_STATE_URI.format(wire_client.get_endpoint())
        self.xml_text = wire_client.fetch_config(uri, wire_client.get_header())
        xml_doc = parse_doc(self.xml_text)

        self.incarnation = findtext(xml_doc, "Incarnation")
        self.expected_state = findtext(xml_doc, "ExpectedState")
        role_instance = find(xml_doc, "RoleInstance")
        self.role_instance_id = findtext(role_instance, "InstanceId")
        role_config = find(role_instance, "Configuration")
        self.role_config_name = findtext(role_config, "ConfigName")
        container = find(xml_doc, "Container")
        self.container_id = findtext(container, "ContainerId")
        lbprobe_ports = find(xml_doc, "LBProbePorts")
        self.load_balancer_probe_port = findtext(lbprobe_ports, "Port")

        GoalState.ContainerID = self.container_id

        fetch_full_goal_state = False
        if full_goal_state:
            fetch_full_goal_state = True
            reason = 'force update'
        elif base_incarnation is not None and self.incarnation != base_incarnation:
            fetch_full_goal_state = True
            reason = 'new incarnation'

        if not fetch_full_goal_state:
            self.hosting_env = None
            self.shared_conf = None
            self.certs = None
            self.ext_conf = None
            self.remote_access = None
            return

        logger.info('Fetching new goal state [incarnation {0} ({1})]', self.incarnation, reason)

        try:
            uri = findtext(xml_doc, "HostingEnvironmentConfig")
            xml_text = wire_client.fetch_config(uri, wire_client.get_header())
            self.hosting_env = HostingEnv(xml_text)

            uri = findtext(xml_doc, "SharedConfig")
            xml_text = wire_client.fetch_config(uri, wire_client.get_header())
            self.shared_conf = SharedConfig(xml_text)

            uri = findtext(xml_doc, "Certificates")
            if uri is None:
                self.certs = None
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header_for_cert())
                self.certs = Certificates(xml_text)

            uri = findtext(xml_doc, "ExtensionsConfig")
            if uri is None:
                self.ext_conf = ExtensionsConfig(None)
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header())
                self.ext_conf = ExtensionsConfig(xml_text)

            uri = findtext(container, "RemoteAccessInfo")
            if uri is None:
                self.remote_access = None
            else:
                xml_text = wire_client.fetch_config(uri, wire_client.get_header_for_cert())
                self.remote_access = RemoteAccess(xml_text)
        except Exception as e:
            logger.warn("Fetching the goal state failed: {0}", ustr(e))
            raise
        finally:
            logger.info('Fetch goal state completed')

    @staticmethod
    def fetch_goal_state(wire_client):
        """
        Fetches the goal state, not including any nested properties (such as extension config).
        """
        return GoalState(wire_client)

    @staticmethod
    def fetch_full_goal_state(wire_client):
        """
        Fetches the full goal state, including nested properties (such as extension config).
        """
        return GoalState(wire_client, full_goal_state=True)

    @staticmethod
    def fetch_full_goal_state_if_incarnation_different_than(wire_client, incarnation):
        """
        Fetches the full goal state if the new incarnation is different than 'incarnation', otherwise returns None.
        """
        goal_state = GoalState(wire_client, base_incarnation=incarnation)
        return goal_state if goal_state.incarnation != incarnation else None


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


class Certificates(object):
    def __init__(self, xml_text):
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
        certificateFormat = findtext(xml_doc, "Format")
        if certificateFormat and certificateFormat != "Pkcs7BlobWithPfxContents":
            logger.warn("The Format is not Pkcs7BlobWithPfxContents. Format is " + certificateFormat)
            return

        cryptutil = CryptUtil(conf.get_openssl_cmd())
        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n"
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
        begin_crt = False
        begin_prv = False
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


class ExtensionsConfig(object):
    def __init__(self, xml_text):
        self.xml_text = xml_text
        self.ext_handlers = ExtHandlerList()
        self.vmagent_manifests = VMAgentManifestList()
        self.status_upload_blob = None
        self.status_upload_blob_type = None
        self.artifacts_profile_blob = None

        if xml_text is None:
            return

        xml_doc = parse_doc(self.xml_text)

        ga_families_list = find(xml_doc, "GAFamilies")
        ga_families = findall(ga_families_list, "GAFamily")

        for ga_family in ga_families:
            family = findtext(ga_family, "Name")
            uris_list = find(ga_family, "Uris")
            uris = findall(uris_list, "Uri")
            manifest = VMAgentManifest()
            manifest.family = family
            for uri in uris:
                manifestUri = VMAgentManifestUri(uri=gettext(uri))
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

        self.status_upload_blob = findtext(xml_doc, "StatusUploadBlob")
        self.artifacts_profile_blob = findtext(xml_doc, "InVMArtifactsProfileBlob")

        status_upload_node = find(xml_doc, "StatusUploadBlob")
        self.status_upload_blob_type = getattrib(status_upload_node, "statusBlobType")
        logger.verbose("Extension config shows status blob type as [{0}]", self.status_upload_blob_type)

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
    def _parse_plugin_settings(ext_handler, plugin_settings):
        if plugin_settings is None:
            return

        name = ext_handler.name
        version = ext_handler.properties.version
        settings = [x for x in plugin_settings \
                    if getattrib(x, "name") == name and \
                    getattrib(x, "version") == version]

        if settings is None or len(settings) == 0:
            return

        runtime_settings = None
        runtime_settings_node = find(settings[0], "RuntimeSettings")
        seqNo = getattrib(runtime_settings_node, "seqNo")
        runtime_settings_str = gettext(runtime_settings_node)
        try:
            runtime_settings = json.loads(runtime_settings_str)
        except ValueError as e:
            logger.error("Invalid extension settings")
            return

        depends_on_level = 0
        depends_on_node = find(settings[0], "DependsOn")
        if depends_on_node != None:
            try:
                depends_on_level = int(getattrib(depends_on_node, "dependencyLevel"))
            except (ValueError, TypeError):
                logger.warn("Could not parse dependencyLevel for handler {0}. Setting it to 0".format(name))
                depends_on_level = 0

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

