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
from azurelinuxagent.common.exception import ProtocolError, ResourceGoneError, VmSettingsError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import ExtensionsGoalStateFromVmSettings
from azurelinuxagent.common.protocol.hostplugin import VmSettingsNotSupported
from azurelinuxagent.common.protocol.restapi import Cert, CertList, RemoteAccessUser, RemoteAccessUsersList
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import GoalStateHistory
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext, getattrib
from azurelinuxagent.common.utils.timeutil import create_timestamp

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

            # These "basic" properties come from the initial request to WireServer's goalstate API
            self._incarnation = None
            self._role_instance_id = None
            self._role_config_name = None
            self._container_id = None

            # These "extended" properties come from additional HTTP requests to the URIs included in the basic goal state, or to the HostGAPlugin
            self._extensions_goal_state = None
            self._hosting_env = None
            self._shared_conf = None
            self._certs = None
            self._remote_access = None

            timestamp = create_timestamp()
            xml_text, xml_doc, incarnation = GoalState._fetch_goal_state(self._wire_client)
            self._history = GoalStateHistory(timestamp, incarnation)

            self._initialize_basic_properties(xml_doc)
            self._fetch_extended_goal_state(xml_text, xml_doc)

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

    def update(self, force_update=False):
        """
        Updates the current GoalState instance fetching values from the WireServer/HostGAPlugin as needed
        """
        timestamp = create_timestamp()
        xml_text, xml_doc, incarnation = GoalState._fetch_goal_state(self._wire_client)

        if force_update or self._incarnation != incarnation:
            # If we are fetching a new goal state
            self._history = GoalStateHistory(timestamp, incarnation)
            self._initialize_basic_properties(xml_doc)
            self._fetch_extended_goal_state(xml_text, xml_doc, force_vm_settings_update=force_update)
        else:
            # else ensure the extensions are using the latest vm_settings
            timestamp = create_timestamp()
            vm_settings, vm_settings_updated = self._fetch_vm_settings(force_update=force_update)
            if vm_settings_updated:
                self._history = GoalStateHistory(timestamp, vm_settings.etag)
                self._extensions_goal_state = vm_settings
                self._history.save_vm_settings(vm_settings.get_redacted_text())

    def save_to_history(self, data, file_name):
        self._history.save(data, file_name)

    def _initialize_basic_properties(self, xml_doc):
        self._incarnation = findtext(xml_doc, "Incarnation")
        role_instance = find(xml_doc, "RoleInstance")
        self._role_instance_id = findtext(role_instance, "InstanceId")
        role_config = find(role_instance, "Configuration")
        self._role_config_name = findtext(role_config, "ConfigName")
        container = find(xml_doc, "Container")
        self._container_id = findtext(container, "ContainerId")

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

        return xml_text, xml_doc, incarnation

    def _fetch_vm_settings(self, force_update=False):
        """
        Issues an HTTP request (HostGAPlugin) for the vm settings and returns the response as an ExtensionsGoalStateFromVmSettings.
        """
        vm_settings, vm_settings_updated = (None, False)

        if conf.get_enable_fast_track():
            try:
                vm_settings, vm_settings_updated = self._wire_client.get_host_plugin().fetch_vm_settings(force_update=force_update)

            except VmSettingsNotSupported:
                pass
            except VmSettingsError as exception:
                # ensure we save the vmSettings if there were parsing errors
                self._history.save_vm_settings(ExtensionsGoalStateFromVmSettings.redact(exception.vm_settings_text))
                raise
            except ResourceGoneError:
                # retry after refreshing the HostGAPlugin
                GoalState.update_host_plugin_headers(self._wire_client)
                vm_settings, vm_settings_updated = self._wire_client.get_host_plugin().fetch_vm_settings(force_update=force_update)

        return vm_settings, vm_settings_updated

    def _fetch_extended_goal_state(self, xml_text, xml_doc, force_vm_settings_update=False):
        """
        Issues HTTP requests (WireServer) for each of the URIs in the goal state (ExtensionsConfig, Certificate, Remote Access users, etc)
        and populates the corresponding properties. If the given 'vm_settings' are not None they are used for the extensions goal state,
        otherwise extensionsConfig is used instead.
        """
        try:
            logger.info('Fetching goal state [incarnation {0}]', self._incarnation)

            self._history.save_goal_state(xml_text)

            # Always fetch the ExtensionsConfig, even if it is not needed, and save it for debugging purposes. Once FastTrack is stable this code could be updated to
            # fetch it only when actually needed.
            extensions_config_uri = findtext(xml_doc, "ExtensionsConfig")

            if extensions_config_uri is None:
                extensions_config = ExtensionsGoalStateFactory.create_empty()
            else:
                xml_text = self._wire_client.fetch_config(extensions_config_uri, self._wire_client.get_header())
                extensions_config = ExtensionsGoalStateFactory.create_from_extensions_config(self._incarnation, xml_text, self._wire_client)
                self._history.save_extensions_config(extensions_config.get_redacted_text())

            vm_settings, vm_settings_updated = self._fetch_vm_settings(force_update=force_vm_settings_update)

            if vm_settings is not None:
                self._extensions_goal_state = vm_settings
                if vm_settings_updated:
                    self._history.save_vm_settings(vm_settings.get_redacted_text())
            else:
                self._extensions_goal_state = extensions_config

            hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
            xml_text = self._wire_client.fetch_config(hosting_env_uri, self._wire_client.get_header())
            self._hosting_env = HostingEnv(xml_text)
            self._history.save_hosting_env(xml_text)

            shared_conf_uri = findtext(xml_doc, "SharedConfig")
            xml_text = self._wire_client.fetch_config(shared_conf_uri, self._wire_client.get_header())
            self._shared_conf = SharedConfig(xml_text)
            self._history.save_shared_conf(xml_text)

            certs_uri = findtext(xml_doc, "Certificates")
            if certs_uri is not None:
                # Note that we do not save the certificates to the goal state history
                xml_text = self._wire_client.fetch_config(certs_uri, self._wire_client.get_header_for_cert())
                self._certs = Certificates(xml_text)

            container = find(xml_doc, "Container")
            remote_access_uri = findtext(container, "RemoteAccessInfo")
            if remote_access_uri is not None:
                xml_text = self._wire_client.fetch_config(remote_access_uri, self._wire_client.get_header_for_cert())
                self._remote_access = RemoteAccess(xml_text)
                self._history.save_remote_access(xml_text)

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

