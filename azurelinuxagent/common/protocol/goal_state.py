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
from azurelinuxagent.common.datacontract import set_properties
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ProtocolError, ResourceGoneError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.hostplugin import VmSettingsNotSupported, VmSettingsSupportStopped
from azurelinuxagent.common.protocol.restapi import Cert, CertList, RemoteAccessUser, RemoteAccessUsersList, ExtHandlerPackage, ExtHandlerPackageList
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import GoalStateHistory, SHARED_CONF_FILE_NAME
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib, gettext


GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
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
    RemoteAccessInfo = 0x10
    All = RoleConfig | HostingEnv | SharedConfig | ExtensionsGoalState | RemoteAccessInfo


class GoalStateInconsistentError(ProtocolError):
    """
    Indicates an inconsistency in the goal state (e.g. missing tenant certificate)
    """
    def __init__(self, msg, inner=None):
        super(GoalStateInconsistentError, self).__init__(msg, inner)


class GoalState(object):
    def __init__(self, wire_client, goal_state_properties=GoalStateProperties.All, silent=False):
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
        if not self._goal_state_properties & GoalStateProperties.ExtensionsGoalState:
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

    def update(self, silent=False):
        """
        Updates the current GoalState instance fetching values from the WireServer/HostGAPlugin as needed
        """
        self.logger.silent = silent

        try:
            self._update(force_update=False)
        except GoalStateInconsistentError as e:
            self.logger.warn("Detected an inconsistency in the goal state: {0}", ustr(e))
            self._update(force_update=True)
            self.logger.info("The goal state is consistent")

    def _update(self, force_update):
        #
        # Fetch the goal state from both the HGAP and the WireServer
        #
        timestamp = datetime.datetime.utcnow()

        if force_update:
            self.logger.info("Refreshing goal state and vmSettings")

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

        #
        # Lastly, decide whether to use the vmSettings or extensionsConfig for the extensions goal state
        #
        if goal_state_updated and vm_settings_updated:
            most_recent = vm_settings if vm_settings.created_on_timestamp > extensions_config.created_on_timestamp else extensions_config
        elif goal_state_updated:
            most_recent = extensions_config
        else:  # vm_settings_updated
            most_recent = vm_settings

        if self._extensions_goal_state is None or most_recent.created_on_timestamp >= self._extensions_goal_state.created_on_timestamp:
            self._extensions_goal_state = most_recent

        #
        # For Fast Track goal states, verify that the required certificates are in the goal state.
        #
        # Some scenarios can produce inconsistent goal states. For example, during hibernation/resume, the Fabric goal state changes (the
        # tenant certificate is re-generated when the VM is restarted) *without* the incarnation necessarily changing (e.g. if the incarnation
        # is 1 before the hibernation; on resume the incarnation is set to 1 even though the goal state has a new certificate). If a Fast
        # Track goal state comes after that, the extensions will need the new certificate. The Agent needs to refresh the goal state in that
        # case, to ensure it fetches the new certificate.
        #
        if self._extensions_goal_state.source == GoalStateSource.FastTrack:
            self._check_certificates()

    def _check_certificates(self):
        for extension in self.extensions_goal_state.extensions:
            for settings in extension.settings:
                if settings.protectedSettings is None:
                    continue
                certificates = self.certs.summary
                if not any(settings.certificateThumbprint == c['thumbprint'] for c in certificates):
                    message = "Certificate {0} needed by {1} is missing from the goal state".format(settings.certificateThumbprint, extension.name)
                    raise GoalStateInconsistentError(message)

    def _restore_wire_server_goal_state(self, incarnation, xml_text, xml_doc, vm_settings_support_stopped_error):
        msg = 'The HGAP stopped supporting vmSettings; will fetched the goal state from the WireServer.'
        self.logger.info(msg)
        add_event(op=WALAEventOperation.VmSettings, message=msg)
        self._history = GoalStateHistory(datetime.datetime.utcnow(), incarnation)
        self._history.save_goal_state(xml_text)
        self._extensions_goal_state = self._fetch_full_wire_server_goal_state(incarnation, xml_doc)
        if self._extensions_goal_state.created_on_timestamp < vm_settings_support_stopped_error.timestamp:
            self._extensions_goal_state.is_outdated = True
            msg = "Fetched a Fabric goal state older than the most recent FastTrack goal state; will skip it.\nFabric:    {0}\nFastTrack: {1}".format(
                  self._extensions_goal_state.created_on_timestamp, vm_settings_support_stopped_error.timestamp)
            self.logger.info(msg)
            add_event(op=WALAEventOperation.VmSettings, message=msg)

    def save_to_history(self, data, file_name):
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
                    GoalStateHistory(datetime.datetime.utcnow(), exception.etag).save_vm_settings(exception.vm_settings_text)
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
                self._history.save_extensions_config(extensions_config.get_redacted_text())

            hosting_env = None
            if GoalStateProperties.HostingEnv & self._goal_state_properties:
                hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
                xml_text = self._wire_client.fetch_config(hosting_env_uri, self._wire_client.get_header())
                hosting_env = HostingEnv(xml_text)
                self._history.save_hosting_env(xml_text)

            shared_config = None
            if GoalStateProperties.SharedConfig & self._goal_state_properties:
                shared_conf_uri = findtext(xml_doc, "SharedConfig")
                xml_text = self._wire_client.fetch_config(shared_conf_uri, self._wire_client.get_header())
                shared_config = SharedConfig(xml_text)
                self._history.save_shared_conf(xml_text)
                # SharedConfig.xml is used by other components (Azsec and Singularity/HPC Infiniband), so save it to the agent's root directory as well
                shared_config_file = os.path.join(conf.get_lib_dir(), SHARED_CONF_FILE_NAME)
                try:
                    fileutil.write_file(shared_config_file, xml_text)
                except Exception as e:
                    logger.warn("Failed to save {0}: {1}".format(shared_config, e))

            certs = EmptyCertificates()
            certs_uri = findtext(xml_doc, "Certificates")
            if (GoalStateProperties.ExtensionsGoalState & self._goal_state_properties) and certs_uri is not None:
                xml_text = self._wire_client.fetch_config(certs_uri, self._wire_client.get_header_for_cert())
                certs = Certificates(xml_text, self.logger)
                # Log and save the certificates summary (i.e. the thumbprint but not the certificate itself) to the goal state history
                for c in certs.summary:
                    message = "Downloaded certificate {0}".format(c)
                    self.logger.info(message)
                    add_event(op=WALAEventOperation.GoalState, message=message)
                if len(certs.warnings) > 0:
                    self.logger.warn(certs.warnings)
                    add_event(op=WALAEventOperation.GoalState, message=certs.warnings)
                self._history.save_certificates(json.dumps(certs.summary))

            remote_access = None
            if GoalStateProperties.RemoteAccessInfo & self._goal_state_properties:
                remote_access_uri = findtext(container, "RemoteAccessInfo")
                if remote_access_uri is not None:
                    xml_text = self._wire_client.fetch_config(remote_access_uri, self._wire_client.get_header_for_cert())
                    remote_access = RemoteAccess(xml_text)
                    self._history.save_remote_access(xml_text)

            self._incarnation = incarnation
            self._role_instance_id = role_instance_id
            self._role_config_name = role_config_name
            self._container_id = container_id
            self._hosting_env = hosting_env
            self._shared_conf = shared_config
            self._certs = certs
            self._remote_access = remote_access

            return extensions_config

        except Exception as exception:
            self.logger.warn("Fetching the goal state failed: {0}", ustr(exception))
            raise ProtocolError(msg="Error fetching goal state", inner=exception)
        finally:
            message = 'Fetch goal state completed'
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


class Certificates(object):
    def __init__(self, xml_text, my_logger):
        self.cert_list = CertList()
        self.summary = []  # debugging info
        self.warnings = []

        # Save the certificates
        local_file = os.path.join(conf.get_lib_dir(), CERTS_FILE_NAME)
        fileutil.write_file(local_file, xml_text)

        # Separate the certificates into individual files.
        xml_doc = parse_doc(xml_text)
        data = findtext(xml_doc, "Data")
        if data is None:
            return

        # if the certificates format is not Pkcs7BlobWithPfxContents do not parse it
        certificate_format = findtext(xml_doc, "Format")
        if certificate_format and certificate_format != "Pkcs7BlobWithPfxContents":
            message = "The Format is not Pkcs7BlobWithPfxContents. Format is {0}".format(certificate_format)
            my_logger.warn(message)
            add_event(op=WALAEventOperation.GoalState, message=message)
            return

        cryptutil = CryptUtil(conf.get_openssl_cmd())
        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n"  # pylint: disable=W1308
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
        begin_crt = False  # pylint: disable=W0612
        begin_prv = False  # pylint: disable=W0612
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
            else:
                # Since private key has *no* matching certificate,
                # it will not be named correctly
                self.warnings.append("Found NO matching cert/thumbprint for private key!")

        for pubkey, thumbprint in thumbprints.items():
            has_private_key = pubkey in prvs
            self.summary.append({"thumbprint": thumbprint, "hasPrivateKey": has_private_key})

        for v1_cert in v1_cert_list:
            cert = Cert()
            set_properties("certs", cert, v1_cert)
            self.cert_list.certificates.append(cert)

    @staticmethod
    def _write_to_tmp_file(index, suffix, buf):
        file_name = os.path.join(conf.get_lib_dir(), "{0}.{1}".format(index, suffix))
        fileutil.write_file(file_name, "".join(buf))
        return file_name

class EmptyCertificates:
    def __init__(self):
        self.cert_list = CertList()
        self.summary = []  # debugging info
        self.warnings = []

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


