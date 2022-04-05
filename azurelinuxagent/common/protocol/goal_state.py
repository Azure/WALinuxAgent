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
import os
import re
import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.datacontract import set_properties
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ProtocolError, ResourceGoneError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.hostplugin import VmSettingsNotSupported, VmSettingsSupportStopped
from azurelinuxagent.common.protocol.restapi import Cert, CertList, RemoteAccessUser, RemoteAccessUsersList
from azurelinuxagent.common.utils import fileutil, timeutil
from azurelinuxagent.common.utils.archive import GoalStateHistory
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib


GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PEM_FILE_NAME = "Certificates.pem"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"

_GET_GOAL_STATE_MAX_ATTEMPTS = 6


class GoalState(object):
    def __init__(self, wire_client):
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

            # These properties hold the goal state from the WireServer and are initialized by self._fetch_full_wire_server_goal_state()
            self._incarnation = None
            self._role_instance_id = None
            self._role_config_name = None
            self._container_id = None
            self._hosting_env = None
            self._shared_conf = None
            self._certs = None
            self._remote_access = None

            self.update()

        except Exception as exception:
            # We don't log the error here since fetching the goal state is done every few seconds
            raise ProtocolError(msg="Error fetching goal state", inner=exception)

    @property
    def incarnation(self):
        return self._incarnation

    @property
    def container_id(self):
        return self._container_id

    @property
    def role_instance_id(self):
        return self._role_instance_id

    @property
    def role_config_name(self):
        return self._role_config_name

    @property
    def extensions_goal_state(self):
        return self._extensions_goal_state

    @property
    def certs(self):
        return self._certs

    @property
    def hosting_env(self):
        return self._hosting_env

    @property
    def shared_conf(self):
        return self._shared_conf

    @property
    def remote_access(self):
        return self._remote_access

    @staticmethod
    def update_host_plugin_headers(wire_client):
        """
        Updates the container ID and role config name that are send in the headers of HTTP requests to the HostGAPlugin
        """
        # Fetching the goal state updates the HostGAPlugin so simply trigger the request
        GoalState._fetch_goal_state(wire_client)

    def update(self):
        """
        Updates the current GoalState instance fetching values from the WireServer/HostGAPlugin as needed
        """
        #
        # Fetch the goal state from both the HGAP and the WireServer
        #
        timestamp = timeutil.create_timestamp()

        incarnation, xml_text, xml_doc = GoalState._fetch_goal_state(self._wire_client)
        goal_state_updated = incarnation != self._incarnation
        if goal_state_updated:
            logger.info('Fetched a new incarnation for the WireServer goal state [incarnation {0}]', incarnation)

        vm_settings, vm_settings_updated = None, False
        try:
            vm_settings, vm_settings_updated = GoalState._fetch_vm_settings(self._wire_client)
        except VmSettingsSupportStopped as exception:  # If the HGAP stopped supporting vmSettings, we need to use the goal state from the WireServer
            self._restore_wire_server_goal_state(incarnation, xml_text, xml_doc, exception)
            return

        if vm_settings_updated:
            logger.info("Fetched new vmSettings [HostGAPlugin correlation ID: {0} eTag: {1} source: {2}]", vm_settings.hostga_plugin_correlation_id, vm_settings.etag, vm_settings.source)
        # Ignore the vmSettings if their source is Fabric (processing a Fabric goal state may require the tenant certificate and the vmSettings don't include it.)
        if vm_settings is not None and vm_settings.source == GoalStateSource.Fabric:
            if vm_settings_updated:
                logger.info("The vmSettings originated via Fabric; will ignore them.")
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

        if self._extensions_goal_state is None or most_recent.created_on_timestamp > self._extensions_goal_state.created_on_timestamp:
            self._extensions_goal_state = most_recent

    def _restore_wire_server_goal_state(self, incarnation, xml_text, xml_doc, vm_settings_support_stopped_error):
        logger.info('The HGAP stopped supporting vmSettings; will fetched the goal state from the WireServer.')
        self._history = GoalStateHistory(timeutil.create_timestamp(), incarnation)
        self._history.save_goal_state(xml_text)
        self._extensions_goal_state = self._fetch_full_wire_server_goal_state(incarnation, xml_doc)
        if self._extensions_goal_state.created_on_timestamp < vm_settings_support_stopped_error.timestamp:
            self._extensions_goal_state.is_outdated = True
            msg = "Fetched a Fabric goal state older than the most recent FastTrack goal state; will skip it. (Fabric: {0} FastTrack: {1})".format(
                  self._extensions_goal_state.created_on_timestamp, vm_settings_support_stopped_error.timestamp)
            logger.info(msg)
            add_event(op=WALAEventOperation.VmSettings, message=msg, is_success=True)

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
    def _fetch_vm_settings(wire_client):
        """
        Issues an HTTP request (HostGAPlugin) for the vm settings and returns the response as an ExtensionsGoalState.
        """
        vm_settings, vm_settings_updated = (None, False)

        if conf.get_enable_fast_track():
            try:
                try:
                    vm_settings, vm_settings_updated = wire_client.get_host_plugin().fetch_vm_settings()
                except ResourceGoneError:
                    # retry after refreshing the HostGAPlugin
                    GoalState.update_host_plugin_headers(wire_client)
                    vm_settings, vm_settings_updated = wire_client.get_host_plugin().fetch_vm_settings()

            except VmSettingsSupportStopped:
                raise
            except VmSettingsNotSupported:
                pass
            except VmSettingsParseError as exception:
                # ensure we save the vmSettings if there were parsing errors, but save them only once per ETag
                if not GoalStateHistory.tag_exists(exception.etag):
                    GoalStateHistory(timeutil.create_timestamp(), exception.etag).save_vm_settings(exception.vm_settings_text)
                raise

        return vm_settings, vm_settings_updated

    def _fetch_full_wire_server_goal_state(self, incarnation, xml_doc):
        """
        Issues HTTP requests (to the WireServer) for each of the URIs in the goal state (ExtensionsConfig, Certificate, Remote Access users, etc)
        and populates the corresponding properties.

        Returns the value of ExtensionsConfig.
        """
        try:
            logger.info('Fetching full goal state from the WireServer [incarnation {0}]', incarnation)

            role_instance = find(xml_doc, "RoleInstance")
            role_instance_id = findtext(role_instance, "InstanceId")
            role_config = find(role_instance, "Configuration")
            role_config_name = findtext(role_config, "ConfigName")
            container = find(xml_doc, "Container")
            container_id = findtext(container, "ContainerId")

            extensions_config_uri = findtext(xml_doc, "ExtensionsConfig")
            if extensions_config_uri is None:
                extensions_config = ExtensionsGoalStateFactory.create_empty(incarnation)
            else:
                xml_text = self._wire_client.fetch_config(extensions_config_uri, self._wire_client.get_header())
                extensions_config = ExtensionsGoalStateFactory.create_from_extensions_config(incarnation, xml_text, self._wire_client)
                self._history.save_extensions_config(extensions_config.get_redacted_text())

            hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
            xml_text = self._wire_client.fetch_config(hosting_env_uri, self._wire_client.get_header())
            hosting_env = HostingEnv(xml_text)
            self._history.save_hosting_env(xml_text)

            shared_conf_uri = findtext(xml_doc, "SharedConfig")
            xml_text = self._wire_client.fetch_config(shared_conf_uri, self._wire_client.get_header())
            shared_conf = SharedConfig(xml_text)
            self._history.save_shared_conf(xml_text)

            certs = None
            certs_uri = findtext(xml_doc, "Certificates")
            if certs_uri is not None:
                # Note that we do not save the certificates to the goal state history
                xml_text = self._wire_client.fetch_config(certs_uri, self._wire_client.get_header_for_cert())
                certs = Certificates(xml_text)

            remote_access = None
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
            self._shared_conf = shared_conf
            self._certs = certs
            self._remote_access = remote_access

            return extensions_config

        except Exception as exception:
            logger.warn("Fetching the goal state failed: {0}", ustr(exception))
            raise ProtocolError(msg="Error fetching goal state", inner=exception)
        finally:
            logger.info('Fetch goal state completed')


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

