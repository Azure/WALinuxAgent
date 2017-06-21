# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+

import json
import os
import re
import time
import xml.sax.saxutils as saxutils

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.exception import ProtocolNotFoundError
from azurelinuxagent.common.future import httpclient, bytebuffer
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import *
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, \
    findtext, getattrib, gettext, remove_bom, get_bytes_from_pem, parse_json

VERSION_INFO_URI = "http://{0}/?comp=versions"
GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
HEALTH_REPORT_URI = "http://{0}/machine?comp=health"
ROLE_PROP_URI = "http://{0}/machine?comp=roleProperties"
TELEMETRY_URI = "http://{0}/machine?comp=telemetrydata"

WIRE_SERVER_ADDR_FILE_NAME = "WireServer"
INCARNATION_FILE_NAME = "Incarnation"
GOAL_STATE_FILE_NAME = "GoalState.{0}.xml"
HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
SHARED_CONF_FILE_NAME = "SharedConfig.xml"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PEM_FILE_NAME = "Certificates.pem"
EXT_CONF_FILE_NAME = "ExtensionsConfig.{0}.xml"
MANIFEST_FILE_NAME = "{0}.{1}.manifest.xml"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"

PROTOCOL_VERSION = "2012-11-30"
ENDPOINT_FINE_NAME = "WireServer"

SHORT_WAITING_INTERVAL = 1  # 1 second
LONG_WAITING_INTERVAL = 15  # 15 seconds


class UploadError(HttpError):
    pass


class WireProtocolResourceGone(ProtocolError):
    pass


class WireProtocol(Protocol):
    """Slim layer to adapt wire protocol data to metadata protocol interface"""

    # TODO: Clean-up goal state processing
    #  At present, some methods magically update GoalState (e.g.,
    #  get_vmagent_manifests), others (e.g., get_vmagent_pkgs)
    #  assume its presence. A better approach would make an explicit update
    #  call that returns the incarnation number and
    #  establishes that number the "context" for all other calls (either by
    #  updating the internal state of the protocol or
    #  by having callers pass the incarnation number to the method).

    def __init__(self, endpoint):
        if endpoint is None:
            raise ProtocolError("WireProtocol endpoint is None")
        self.endpoint = endpoint
        self.client = WireClient(self.endpoint)

    def detect(self):
        self.client.check_wire_protocol_version()

        trans_prv_file = os.path.join(conf.get_lib_dir(),
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        cryptutil = CryptUtil(conf.get_openssl_cmd())
        cryptutil.gen_transport_cert(trans_prv_file, trans_cert_file)

        self.client.update_goal_state(forced=True)

    def get_vminfo(self):
        goal_state = self.client.get_goal_state()
        hosting_env = self.client.get_hosting_env()

        vminfo = VMInfo()
        vminfo.subscriptionId = None
        vminfo.vmName = hosting_env.vm_name
        vminfo.tenantName = hosting_env.deployment_name
        vminfo.roleName = hosting_env.role_name
        vminfo.roleInstanceName = goal_state.role_instance_id
        vminfo.containerId = goal_state.container_id
        return vminfo

    def get_certs(self):
        certificates = self.client.get_certs()
        return certificates.cert_list

    def get_vmagent_manifests(self):
        # Update goal state to get latest extensions config
        self.client.update_goal_state()
        goal_state = self.client.get_goal_state()
        ext_conf = self.client.get_ext_conf()
        return ext_conf.vmagent_manifests, goal_state.incarnation

    def get_vmagent_pkgs(self, vmagent_manifest):
        goal_state = self.client.get_goal_state()
        man = self.client.get_gafamily_manifest(vmagent_manifest, goal_state)
        return man.pkg_list

    def get_ext_handlers(self):
        logger.verbose("Get extension handler config")
        # Update goal state to get latest extensions config
        self.client.update_goal_state()
        goal_state = self.client.get_goal_state()
        ext_conf = self.client.get_ext_conf()
        # In wire protocol, incarnation is equivalent to ETag
        return ext_conf.ext_handlers, goal_state.incarnation

    def get_ext_handler_pkgs(self, ext_handler):
        logger.verbose("Get extension handler package")
        goal_state = self.client.get_goal_state()
        man = self.client.get_ext_manifest(ext_handler, goal_state)
        return man.pkg_list

    def get_artifacts_profile(self):
        logger.verbose("Get In-VM Artifacts Profile")
        return self.client.get_artifacts_profile()

    def download_ext_handler_pkg(self, uri, headers=None):
        package = super(WireProtocol, self).download_ext_handler_pkg(uri)

        if package is not None:
            return package
        else:
            logger.warn("Download did not succeed, falling back to host plugin")
            host = self.client.get_host_plugin()
            uri, headers = host.get_artifact_request(uri, host.manifest_uri)
            package = super(WireProtocol, self).download_ext_handler_pkg(uri, headers=headers)
        return package

    def report_provision_status(self, provision_status):
        validate_param("provision_status", provision_status, ProvisionStatus)

        if provision_status.status is not None:
            self.client.report_health(provision_status.status,
                                      provision_status.subStatus,
                                      provision_status.description)
        if provision_status.properties.certificateThumbprint is not None:
            thumbprint = provision_status.properties.certificateThumbprint
            self.client.report_role_prop(thumbprint)

    def report_vm_status(self, vm_status):
        validate_param("vm_status", vm_status, VMStatus)
        self.client.status_blob.set_vm_status(vm_status)
        self.client.upload_status_blob()

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        validate_param("ext_status", ext_status, ExtensionStatus)
        self.client.status_blob.set_ext_status(ext_handler_name, ext_status)

    def report_event(self, events):
        validate_param("events", events, TelemetryEventList)
        self.client.report_event(events)


def _build_role_properties(container_id, role_instance_id, thumbprint):
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
           u"<RoleProperties>"
           u"<Container>"
           u"<ContainerId>{0}</ContainerId>"
           u"<RoleInstances>"
           u"<RoleInstance>"
           u"<Id>{1}</Id>"
           u"<Properties>"
           u"<Property name=\"CertificateThumbprint\" value=\"{2}\" />"
           u"</Properties>"
           u"</RoleInstance>"
           u"</RoleInstances>"
           u"</Container>"
           u"</RoleProperties>"
           u"").format(container_id, role_instance_id, thumbprint)
    return xml


def _build_health_report(incarnation, container_id, role_instance_id,
                         status, substatus, description):
    # Escape '&', '<' and '>'
    description = saxutils.escape(ustr(description))
    detail = u''
    if substatus is not None:
        substatus = saxutils.escape(ustr(substatus))
        detail = (u"<Details>"
                  u"<SubStatus>{0}</SubStatus>"
                  u"<Description>{1}</Description>"
                  u"</Details>").format(substatus, description)
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
           u"<Health "
           u"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
           u" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
           u"<GoalStateIncarnation>{0}</GoalStateIncarnation>"
           u"<Container>"
           u"<ContainerId>{1}</ContainerId>"
           u"<RoleInstanceList>"
           u"<Role>"
           u"<InstanceId>{2}</InstanceId>"
           u"<Health>"
           u"<State>{3}</State>"
           u"{4}"
           u"</Health>"
           u"</Role>"
           u"</RoleInstanceList>"
           u"</Container>"
           u"</Health>"
           u"").format(incarnation,
                       container_id,
                       role_instance_id,
                       status,
                       detail)
    return xml


"""
Convert VMStatus object to status blob format
"""


def ga_status_to_v1(ga_status):
    formatted_msg = {
        'lang': 'en-US',
        'message': ga_status.message
    }
    v1_ga_status = {
        'version': ga_status.version,
        'status': ga_status.status,
        'osversion': ga_status.osversion,
        'osname': ga_status.osname,
        'hostname': ga_status.hostname,
        'formattedMessage': formatted_msg
    }
    return v1_ga_status


def ext_substatus_to_v1(sub_status_list):
    status_list = []
    for substatus in sub_status_list:
        status = {
            "name": substatus.name,
            "status": substatus.status,
            "code": substatus.code,
            "formattedMessage": {
                "lang": "en-US",
                "message": substatus.message
            }
        }
        status_list.append(status)
    return status_list


def ext_status_to_v1(ext_name, ext_status):
    if ext_status is None:
        return None
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    v1_sub_status = ext_substatus_to_v1(ext_status.substatusList)
    v1_ext_status = {
        "status": {
            "name": ext_name,
            "configurationAppliedTime": ext_status.configurationAppliedTime,
            "operation": ext_status.operation,
            "status": ext_status.status,
            "code": ext_status.code,
            "formattedMessage": {
                "lang": "en-US",
                "message": ext_status.message
            }
        },
        "version": 1.0,
        "timestampUTC": timestamp
    }
    if len(v1_sub_status) != 0:
        v1_ext_status['status']['substatus'] = v1_sub_status
    return v1_ext_status


def ext_handler_status_to_v1(handler_status, ext_statuses, timestamp):
    v1_handler_status = {
        'handlerVersion': handler_status.version,
        'handlerName': handler_status.name,
        'status': handler_status.status,
        'code': handler_status.code
    }
    if handler_status.message is not None:
        v1_handler_status["formattedMessage"] = {
            "lang": "en-US",
            "message": handler_status.message
        }

    if len(handler_status.extensions) > 0:
        # Currently, no more than one extension per handler
        ext_name = handler_status.extensions[0]
        ext_status = ext_statuses.get(ext_name)
        v1_ext_status = ext_status_to_v1(ext_name, ext_status)
        if ext_status is not None and v1_ext_status is not None:
            v1_handler_status["runtimeSettingsStatus"] = {
                'settingsStatus': v1_ext_status,
                'sequenceNumber': ext_status.sequenceNumber
            }
    return v1_handler_status


def vm_status_to_v1(vm_status, ext_statuses):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    v1_ga_status = ga_status_to_v1(vm_status.vmAgent)
    v1_handler_status_list = []
    for handler_status in vm_status.vmAgent.extensionHandlers:
        v1_handler_status = ext_handler_status_to_v1(handler_status,
                                                     ext_statuses, timestamp)
        if v1_handler_status is not None:
            v1_handler_status_list.append(v1_handler_status)

    v1_agg_status = {
        'guestAgentStatus': v1_ga_status,
        'handlerAggregateStatus': v1_handler_status_list
    }
    v1_vm_status = {
        'version': '1.1',
        'timestampUTC': timestamp,
        'aggregateStatus': v1_agg_status
    }
    return v1_vm_status


class StatusBlob(object):
    def __init__(self, client):
        self.vm_status = None
        self.ext_statuses = {}
        self.client = client
        self.type = None
        self.data = None

    def set_vm_status(self, vm_status):
        validate_param("vmAgent", vm_status, VMStatus)
        self.vm_status = vm_status

    def set_ext_status(self, ext_handler_name, ext_status):
        validate_param("extensionStatus", ext_status, ExtensionStatus)
        self.ext_statuses[ext_handler_name] = ext_status

    def to_json(self):
        report = vm_status_to_v1(self.vm_status, self.ext_statuses)
        return json.dumps(report)

    __storage_version__ = "2014-02-14"

    def prepare(self, blob_type):
        logger.verbose("Prepare status blob")
        self.data = self.to_json()
        self.type = blob_type

    def upload(self, url):
        try:
            if not self.type in ["BlockBlob", "PageBlob"]:
                raise ProtocolError("Illegal blob type: {0}".format(self.type))

            if self.type == "BlockBlob":
                self.put_block_blob(url, self.data)
            else:
                self.put_page_blob(url, self.data)
            return True

        except Exception as e:
            logger.verbose("Initial status upload failed: {0}", e)

        return False

    def get_block_blob_headers(self, blob_size):
        return {
            "Content-Length": ustr(blob_size),
            "x-ms-blob-type": "BlockBlob",
            "x-ms-date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "x-ms-version": self.__class__.__storage_version__
        }

    def put_block_blob(self, url, data):
        logger.verbose("Put block blob")
        headers = self.get_block_blob_headers(len(data))
        resp = self.client.call_storage_service(restutil.http_put, url, data, headers)
        if resp.status != httpclient.CREATED:
            raise UploadError(
                "Failed to upload block blob: {0}".format(resp.status))

    def get_page_blob_create_headers(self, blob_size):
        return {
            "Content-Length": "0",
            "x-ms-blob-content-length": ustr(blob_size),
            "x-ms-blob-type": "PageBlob",
            "x-ms-date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "x-ms-version": self.__class__.__storage_version__
        }

    def get_page_blob_page_headers(self, start, end):
        return {
            "Content-Length": ustr(end - start),
            "x-ms-date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "x-ms-range": "bytes={0}-{1}".format(start, end - 1),
            "x-ms-page-write": "update",
            "x-ms-version": self.__class__.__storage_version__
        }

    def put_page_blob(self, url, data):
        logger.verbose("Put page blob")

        # Convert string into bytes and align to 512 bytes
        data = bytearray(data, encoding='utf-8')
        page_blob_size = int((len(data) + 511) / 512) * 512

        headers = self.get_page_blob_create_headers(page_blob_size)
        resp = self.client.call_storage_service(restutil.http_put, url, "", headers)
        if resp.status != httpclient.CREATED:
            raise UploadError(
                "Failed to clean up page blob: {0}".format(resp.status))

        if url.count("?") <= 0:
            url = "{0}?comp=page".format(url)
        else:
            url = "{0}&comp=page".format(url)

        logger.verbose("Upload page blob")
        page_max = 4 * 1024 * 1024  # Max page size: 4MB
        start = 0
        end = 0
        while end < len(data):
            end = min(len(data), start + page_max)
            content_size = end - start
            # Align to 512 bytes
            page_end = int((end + 511) / 512) * 512
            buf_size = page_end - start
            buf = bytearray(buf_size)
            buf[0: content_size] = data[start: end]
            headers = self.get_page_blob_page_headers(start, page_end)
            resp = self.client.call_storage_service(
                restutil.http_put,
                url,
                bytebuffer(buf),
                headers)
            if resp is None or resp.status != httpclient.CREATED:
                raise UploadError(
                    "Failed to upload page blob: {0}".format(resp.status))
            start = end


def event_param_to_v1(param):
    param_format = '<Param Name="{0}" Value={1} T="{2}" />'
    param_type = type(param.value)
    attr_type = ""
    if param_type is int:
        attr_type = 'mt:uint64'
    elif param_type is str:
        attr_type = 'mt:wstr'
    elif ustr(param_type).count("'unicode'") > 0:
        attr_type = 'mt:wstr'
    elif param_type is bool:
        attr_type = 'mt:bool'
    elif param_type is float:
        attr_type = 'mt:float64'
    return param_format.format(param.name,
                               saxutils.quoteattr(ustr(param.value)),
                               attr_type)


def event_to_v1(event):
    params = ""
    for param in event.parameters:
        params += event_param_to_v1(param)
    event_str = ('<Event id="{0}">'
                 '<![CDATA[{1}]]>'
                 '</Event>').format(event.eventId, params)
    return event_str


class WireClient(object):
    def __init__(self, endpoint):
        logger.info("Wire server endpoint:{0}", endpoint)
        self.endpoint = endpoint
        self.goal_state = None
        self.updated = None
        self.hosting_env = None
        self.shared_conf = None
        self.certs = None
        self.ext_conf = None
        self.last_request = 0
        self.req_count = 0
        self.host_plugin = None
        self.status_blob = StatusBlob(self)

    def prevent_throttling(self):
        """
        Try to avoid throttling of wire server
        """
        now = time.time()
        if now - self.last_request < 1:
            logger.verbose("Last request issued less than 1 second ago")
            logger.verbose("Sleep {0} second to avoid throttling.",
                           SHORT_WAITING_INTERVAL)
            time.sleep(SHORT_WAITING_INTERVAL)
        self.last_request = now

        self.req_count += 1
        if self.req_count % 3 == 0:
            logger.verbose("Sleep {0} second to avoid throttling.",
                           SHORT_WAITING_INTERVAL)
            time.sleep(SHORT_WAITING_INTERVAL)
            self.req_count = 0

    def call_wireserver(self, http_req, *args, **kwargs):
        """
        Call wire server; handle throttling (403), resource gone (410) and
        service unavailable (503).
        """
        self.prevent_throttling()
        for retry in range(0, 3):
            resp = http_req(*args, **kwargs)
            if resp.status == httpclient.FORBIDDEN:
                logger.warn("Sending too many requests to wire server. ")
                logger.info("Sleeping {0}s to avoid throttling.",
                            LONG_WAITING_INTERVAL)
                time.sleep(LONG_WAITING_INTERVAL)
            elif resp.status == httpclient.SERVICE_UNAVAILABLE:
                logger.warn("Service temporarily unavailable, sleeping {0}s "
                            "before retrying.", LONG_WAITING_INTERVAL)
                time.sleep(LONG_WAITING_INTERVAL)
            elif resp.status == httpclient.GONE:
                msg = args[0] if len(args) > 0 else ""
                raise WireProtocolResourceGone(msg)
            else:
                return resp
        raise ProtocolError(("Calling wire server failed: "
                             "{0}").format(resp.status))

    def decode_config(self, data):
        if data is None:
            return None
        data = remove_bom(data)
        xml_text = ustr(data, encoding='utf-8')
        return xml_text

    def fetch_config(self, uri, headers):
        try:
            resp = self.call_wireserver(restutil.http_get,
                                        uri,
                                        headers=headers)
        except HttpError as e:
            raise ProtocolError(ustr(e))

        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - {1}".format(resp.status, uri))

        return self.decode_config(resp.read())

    def fetch_cache(self, local_file):
        if not os.path.isfile(local_file):
            raise ProtocolError("{0} is missing.".format(local_file))
        try:
            return fileutil.read_file(local_file)
        except IOError as e:
            raise ProtocolError("Failed to read cache: {0}".format(e))

    def save_cache(self, local_file, data):
        try:
            fileutil.write_file(local_file, data)
        except IOError as e:
            raise ProtocolError("Failed to write cache: {0}".format(e))

    @staticmethod
    def call_storage_service(http_req, *args, **kwargs):
        """ 
        Call storage service, handle SERVICE_UNAVAILABLE(503)
        """

        # Default to use the configured HTTP proxy
        if not 'chk_proxy' in kwargs or kwargs['chk_proxy'] is None:
            kwargs['chk_proxy'] = True

        for retry in range(0, 3):
            resp = http_req(*args, **kwargs)
            if resp.status == httpclient.SERVICE_UNAVAILABLE:
                logger.warn("Storage service is temporarily unavailable. ")
                logger.info("Will retry in {0} seconds. ",
                            LONG_WAITING_INTERVAL)
                time.sleep(LONG_WAITING_INTERVAL)
            else:
                return resp
        raise ProtocolError(("Calling storage endpoint failed: "
                             "{0}").format(resp.status))

    def fetch_manifest(self, version_uris):
        logger.verbose("Fetch manifest")
        for version in version_uris:
            response = None
            if not HostPluginProtocol.is_default_channel():
                response = self.fetch(version.uri)
            if not response:
                if HostPluginProtocol.is_default_channel():
                    logger.verbose("Using host plugin as default channel")
                else:
                    logger.verbose("Manifest could not be downloaded, falling back to host plugin")
                host = self.get_host_plugin()
                uri, headers = host.get_artifact_request(version.uri)
                response = self.fetch(uri, headers, chk_proxy=False)
                if not response:
                    host = self.get_host_plugin(force_update=True)
                    logger.info("Retry fetch in {0} seconds",
                                SHORT_WAITING_INTERVAL)
                    time.sleep(SHORT_WAITING_INTERVAL)
                else:
                    host.manifest_uri = version.uri
                    logger.verbose("Manifest downloaded successfully from host plugin")
                    if not HostPluginProtocol.is_default_channel():
                        logger.info("Setting host plugin as default channel")
                        HostPluginProtocol.set_default_channel(True)
            if response:
                return response
        raise ProtocolError("Failed to fetch manifest from all sources")

    def fetch(self, uri, headers=None, chk_proxy=None):
        logger.verbose("Fetch [{0}] with headers [{1}]", uri, headers)
        return_value = None
        try:
            resp = self.call_storage_service(
                restutil.http_get,
                uri,
                headers,
                chk_proxy=chk_proxy)
            if resp.status == httpclient.OK:
                return_value = self.decode_config(resp.read())
            else:
                logger.warn("Could not fetch {0} [{1}]",
                            uri,
                            HostPluginProtocol.read_response_error(resp))
        except (HttpError, ProtocolError) as e:
            logger.verbose("Fetch failed from [{0}]: {1}", uri, e)
        return return_value

    def update_hosting_env(self, goal_state):
        if goal_state.hosting_env_uri is None:
            raise ProtocolError("HostingEnvironmentConfig uri is empty")
        local_file = os.path.join(conf.get_lib_dir(), HOSTING_ENV_FILE_NAME)
        xml_text = self.fetch_config(goal_state.hosting_env_uri,
                                     self.get_header())
        self.save_cache(local_file, xml_text)
        self.hosting_env = HostingEnv(xml_text)

    def update_shared_conf(self, goal_state):
        if goal_state.shared_conf_uri is None:
            raise ProtocolError("SharedConfig uri is empty")
        local_file = os.path.join(conf.get_lib_dir(), SHARED_CONF_FILE_NAME)
        xml_text = self.fetch_config(goal_state.shared_conf_uri,
                                     self.get_header())
        self.save_cache(local_file, xml_text)
        self.shared_conf = SharedConfig(xml_text)

    def update_certs(self, goal_state):
        if goal_state.certs_uri is None:
            return
        local_file = os.path.join(conf.get_lib_dir(), CERTS_FILE_NAME)
        xml_text = self.fetch_config(goal_state.certs_uri,
                                     self.get_header_for_cert())
        self.save_cache(local_file, xml_text)
        self.certs = Certificates(self, xml_text)

    def update_ext_conf(self, goal_state):
        if goal_state.ext_uri is None:
            logger.info("ExtensionsConfig.xml uri is empty")
            self.ext_conf = ExtensionsConfig(None)
            return
        incarnation = goal_state.incarnation
        local_file = os.path.join(conf.get_lib_dir(),
                                  EXT_CONF_FILE_NAME.format(incarnation))
        xml_text = self.fetch_config(goal_state.ext_uri, self.get_header())
        self.save_cache(local_file, xml_text)
        self.ext_conf = ExtensionsConfig(xml_text)

    def update_goal_state(self, forced=False, max_retry=3):
        uri = GOAL_STATE_URI.format(self.endpoint)
        xml_text = self.fetch_config(uri, self.get_header())
        goal_state = GoalState(xml_text)

        incarnation_file = os.path.join(conf.get_lib_dir(),
                                        INCARNATION_FILE_NAME)

        if not forced:
            last_incarnation = None
            if os.path.isfile(incarnation_file):
                last_incarnation = fileutil.read_file(incarnation_file)
            new_incarnation = goal_state.incarnation
            if last_incarnation is not None and \
                            last_incarnation == new_incarnation:
                # Goalstate is not updated.
                return

        # Start updating goalstate, retry on 410
        for retry in range(0, max_retry):
            try:
                self.goal_state = goal_state
                file_name = GOAL_STATE_FILE_NAME.format(goal_state.incarnation)
                goal_state_file = os.path.join(conf.get_lib_dir(), file_name)
                self.save_cache(goal_state_file, xml_text)
                self.update_hosting_env(goal_state)
                self.update_shared_conf(goal_state)
                self.update_certs(goal_state)
                self.update_ext_conf(goal_state)
                self.save_cache(incarnation_file, goal_state.incarnation)
                if self.host_plugin is not None:
                    self.host_plugin.container_id = goal_state.container_id
                    self.host_plugin.role_config_name = goal_state.role_config_name
                return
            except WireProtocolResourceGone:
                logger.info("Incarnation is out of date. Update goalstate.")
                xml_text = self.fetch_config(uri, self.get_header())
                goal_state = GoalState(xml_text)

        raise ProtocolError("Exceeded max retry updating goal state")

    def get_goal_state(self):
        if self.goal_state is None:
            incarnation_file = os.path.join(conf.get_lib_dir(),
                                            INCARNATION_FILE_NAME)
            incarnation = self.fetch_cache(incarnation_file)

            file_name = GOAL_STATE_FILE_NAME.format(incarnation)
            goal_state_file = os.path.join(conf.get_lib_dir(), file_name)
            xml_text = self.fetch_cache(goal_state_file)
            self.goal_state = GoalState(xml_text)
        return self.goal_state

    def get_hosting_env(self):
        if self.hosting_env is None:
            local_file = os.path.join(conf.get_lib_dir(),
                                      HOSTING_ENV_FILE_NAME)
            xml_text = self.fetch_cache(local_file)
            self.hosting_env = HostingEnv(xml_text)
        return self.hosting_env

    def get_shared_conf(self):
        if self.shared_conf is None:
            local_file = os.path.join(conf.get_lib_dir(),
                                      SHARED_CONF_FILE_NAME)
            xml_text = self.fetch_cache(local_file)
            self.shared_conf = SharedConfig(xml_text)
        return self.shared_conf

    def get_certs(self):
        if self.certs is None:
            local_file = os.path.join(conf.get_lib_dir(), CERTS_FILE_NAME)
            xml_text = self.fetch_cache(local_file)
            self.certs = Certificates(self, xml_text)
        if self.certs is None:
            return None
        return self.certs

    def get_ext_conf(self):
        if self.ext_conf is None:
            goal_state = self.get_goal_state()
            if goal_state.ext_uri is None:
                self.ext_conf = ExtensionsConfig(None)
            else:
                local_file = EXT_CONF_FILE_NAME.format(goal_state.incarnation)
                local_file = os.path.join(conf.get_lib_dir(), local_file)
                xml_text = self.fetch_cache(local_file)
                self.ext_conf = ExtensionsConfig(xml_text)
        return self.ext_conf

    def get_ext_manifest(self, ext_handler, goal_state):
        local_file = MANIFEST_FILE_NAME.format(ext_handler.name,
                                               goal_state.incarnation)
        local_file = os.path.join(conf.get_lib_dir(), local_file)
        xml_text = self.fetch_manifest(ext_handler.versionUris)
        self.save_cache(local_file, xml_text)
        return ExtensionManifest(xml_text)

    def get_gafamily_manifest(self, vmagent_manifest, goal_state):
        local_file = MANIFEST_FILE_NAME.format(vmagent_manifest.family,
                                               goal_state.incarnation)
        local_file = os.path.join(conf.get_lib_dir(), local_file)
        xml_text = self.fetch_manifest(vmagent_manifest.versionsManifestUris)
        fileutil.write_file(local_file, xml_text)
        return ExtensionManifest(xml_text)

    def check_wire_protocol_version(self):
        uri = VERSION_INFO_URI.format(self.endpoint)
        version_info_xml = self.fetch_config(uri, None)
        version_info = VersionInfo(version_info_xml)

        preferred = version_info.get_preferred()
        if PROTOCOL_VERSION == preferred:
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
        elif PROTOCOL_VERSION in version_info.get_supported():
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
            logger.warn("Server preferred version:{0}", preferred)
        else:
            error = ("Agent supported wire protocol version: {0} was not "
                     "advised by Fabric.").format(PROTOCOL_VERSION)
            raise ProtocolNotFoundError(error)

    def upload_status_blob(self):
        ext_conf = self.get_ext_conf()

        blob_uri = ext_conf.status_upload_blob
        blob_type = ext_conf.status_upload_blob_type

        if blob_uri is not None:

            if not blob_type in ["BlockBlob", "PageBlob"]:
                blob_type = "BlockBlob"
                logger.verbose("Status Blob type is unspecified "
                    "-- assuming it is a BlockBlob")

            try:
                self.status_blob.prepare(blob_type)
            except Exception as e:
                self.report_status_event(
                    "Exception creating status blob: {0}",
                    e)
                return

            uploaded = False
            if not HostPluginProtocol.is_default_channel():
                try:
                    uploaded = self.status_blob.upload(blob_uri)
                except HttpError as e:
                    pass

            if not uploaded:
                host = self.get_host_plugin()
                host.put_vm_status(self.status_blob,
                                   ext_conf.status_upload_blob,
                                   ext_conf.status_upload_blob_type)

    def report_role_prop(self, thumbprint):
        goal_state = self.get_goal_state()
        role_prop = _build_role_properties(goal_state.container_id,
                                           goal_state.role_instance_id,
                                           thumbprint)
        role_prop = role_prop.encode("utf-8")
        role_prop_uri = ROLE_PROP_URI.format(self.endpoint)
        headers = self.get_header_for_xml_content()
        try:
            resp = self.call_wireserver(restutil.http_post,
                                        role_prop_uri,
                                        role_prop,
                                        headers=headers)
        except HttpError as e:
            raise ProtocolError((u"Failed to send role properties: "
                                 u"{0}").format(e))
        if resp.status != httpclient.ACCEPTED:
            raise ProtocolError((u"Failed to send role properties: "
                                 u",{0}: {1}").format(resp.status,
                                                      resp.read()))

    def report_health(self, status, substatus, description):
        goal_state = self.get_goal_state()
        health_report = _build_health_report(goal_state.incarnation,
                                             goal_state.container_id,
                                             goal_state.role_instance_id,
                                             status,
                                             substatus,
                                             description)
        health_report = health_report.encode("utf-8")
        health_report_uri = HEALTH_REPORT_URI.format(self.endpoint)
        headers = self.get_header_for_xml_content()
        try:
            # 30 retries with 10s sleep gives ~5min for wireserver updates;
            # this is retried 3 times with 15s sleep before throwing a
            # ProtocolError, for a total of ~15min.
            resp = self.call_wireserver(restutil.http_post,
                                        health_report_uri,
                                        health_report,
                                        headers=headers,
                                        max_retry=30)
        except HttpError as e:
            raise ProtocolError((u"Failed to send provision status: "
                                 u"{0}").format(e))
        if resp.status != httpclient.OK:
            raise ProtocolError((u"Failed to send provision status: "
                                 u",{0}: {1}").format(resp.status,
                                                      resp.read()))

    def send_event(self, provider_id, event_str):
        uri = TELEMETRY_URI.format(self.endpoint)
        data_format = ('<?xml version="1.0"?>'
                       '<TelemetryData version="1.0">'
                       '<Provider id="{0}">{1}'
                       '</Provider>'
                       '</TelemetryData>')
        data = data_format.format(provider_id, event_str)
        try:
            header = self.get_header_for_xml_content()
            resp = self.call_wireserver(restutil.http_post, uri, data, header)
        except HttpError as e:
            raise ProtocolError("Failed to send events:{0}".format(e))

        if resp.status != httpclient.OK:
            logger.verbose(resp.read())
            raise ProtocolError(
                "Failed to send events:{0}".format(resp.status))

    def report_event(self, event_list):
        buf = {}
        # Group events by providerId
        for event in event_list.events:
            if event.providerId not in buf:
                buf[event.providerId] = ""
            event_str = event_to_v1(event)
            if len(event_str) >= 63 * 1024:
                logger.warn("Single event too large: {0}", event_str[300:])
                continue
            if len(buf[event.providerId] + event_str) >= 63 * 1024:
                self.send_event(event.providerId, buf[event.providerId])
                buf[event.providerId] = ""
            buf[event.providerId] = buf[event.providerId] + event_str

        # Send out all events left in buffer.
        for provider_id in list(buf.keys()):
            if len(buf[provider_id]) > 0:
                self.send_event(provider_id, buf[provider_id])

    def report_status_event(self, message, *args):
        from azurelinuxagent.common.event import report_event, \
                WALAEventOperation

        message = message.format(*args)
        logger.warn(message)
        report_event(op=WALAEventOperation.ReportStatus,
                    is_success=False,
                    message=message)

    def get_header(self):
        return {
            "x-ms-agent-name": "WALinuxAgent",
            "x-ms-version": PROTOCOL_VERSION
        }

    def get_header_for_xml_content(self):
        return {
            "x-ms-agent-name": "WALinuxAgent",
            "x-ms-version": PROTOCOL_VERSION,
            "Content-Type": "text/xml;charset=utf-8"
        }

    def get_header_for_cert(self):
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        content = self.fetch_cache(trans_cert_file)
        cert = get_bytes_from_pem(content)
        return {
            "x-ms-agent-name": "WALinuxAgent",
            "x-ms-version": PROTOCOL_VERSION,
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert": cert
        }

    def get_host_plugin(self, force_update=False):
        if self.host_plugin is None or force_update:
            if force_update:
                logger.warn("Forcing update of goal state")
                self.goal_state = None
                self.update_goal_state(forced=True)
            goal_state = self.get_goal_state()
            self.host_plugin = HostPluginProtocol(self.endpoint,
                                                  goal_state.container_id,
                                                  goal_state.role_config_name)
        return self.host_plugin

    def has_artifacts_profile_blob(self):
        return self.ext_conf and not \
               textutil.is_str_none_or_whitespace(self.ext_conf.artifacts_profile_blob)

    def get_artifacts_profile(self):
        artifacts_profile = None
        if self.has_artifacts_profile_blob():
            blob = self.ext_conf.artifacts_profile_blob
            logger.verbose("Getting the artifacts profile")
            profile = self.fetch(blob)

            if profile is None:
                logger.warn("Download failed, falling back to host plugin")
                host = self.get_host_plugin()
                uri, headers = host.get_artifact_request(blob)
                profile = self.decode_config(self.fetch(uri, headers, chk_proxy=False))

            if not textutil.is_str_none_or_whitespace(profile):
                    logger.verbose("Artifacts profile downloaded successfully")
                    artifacts_profile = InVMArtifactsProfile(profile)

        return artifacts_profile


class VersionInfo(object):
    def __init__(self, xml_text):
        """
        Query endpoint server for wire protocol version.
        Fail if our desired protocol version is not seen.
        """
        logger.verbose("Load Version.xml")
        self.parse(xml_text)

    def parse(self, xml_text):
        xml_doc = parse_doc(xml_text)
        preferred = find(xml_doc, "Preferred")
        self.preferred = findtext(preferred, "Version")
        logger.info("Fabric preferred wire protocol version:{0}",
                    self.preferred)

        self.supported = []
        supported = find(xml_doc, "Supported")
        supported_version = findall(supported, "Version")
        for node in supported_version:
            version = gettext(node)
            logger.verbose("Fabric supported wire protocol version:{0}",
                           version)
            self.supported.append(version)

    def get_preferred(self):
        return self.preferred

    def get_supported(self):
        return self.supported


class GoalState(object):
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("GoalState.xml is None")
        logger.verbose("Load GoalState.xml")
        self.incarnation = None
        self.expected_state = None
        self.hosting_env_uri = None
        self.shared_conf_uri = None
        self.certs_uri = None
        self.ext_uri = None
        self.role_instance_id = None
        self.role_config_name = None
        self.container_id = None
        self.load_balancer_probe_port = None
        self.xml_text = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Request configuration data from endpoint server.
        """
        self.xml_text = xml_text
        xml_doc = parse_doc(xml_text)
        self.incarnation = findtext(xml_doc, "Incarnation")
        self.expected_state = findtext(xml_doc, "ExpectedState")
        self.hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
        self.shared_conf_uri = findtext(xml_doc, "SharedConfig")
        self.certs_uri = findtext(xml_doc, "Certificates")
        self.ext_uri = findtext(xml_doc, "ExtensionsConfig")
        role_instance = find(xml_doc, "RoleInstance")
        self.role_instance_id = findtext(role_instance, "InstanceId")
        role_config = find(role_instance, "Configuration")
        self.role_config_name = findtext(role_config, "ConfigName")
        container = find(xml_doc, "Container")
        self.container_id = findtext(container, "ContainerId")
        lbprobe_ports = find(xml_doc, "LBProbePorts")
        self.load_balancer_probe_port = findtext(lbprobe_ports, "Port")
        return self


class HostingEnv(object):
    """
    parse Hosting enviromnet config and store in
    HostingEnvironmentConfig.xml
    """

    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("HostingEnvironmentConfig.xml is None")
        logger.verbose("Load HostingEnvironmentConfig.xml")
        self.vm_name = None
        self.role_name = None
        self.deployment_name = None
        self.xml_text = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        parse and create HostingEnvironmentConfig.xml.
        """
        self.xml_text = xml_text
        xml_doc = parse_doc(xml_text)
        incarnation = find(xml_doc, "Incarnation")
        self.vm_name = getattrib(incarnation, "instance")
        role = find(xml_doc, "Role")
        self.role_name = getattrib(role, "name")
        deployment = find(xml_doc, "Deployment")
        self.deployment_name = getattrib(deployment, "name")
        return self


class SharedConfig(object):
    """
    parse role endpoint server and goal state config.
    """

    def __init__(self, xml_text):
        logger.verbose("Load SharedConfig.xml")
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        parse and write configuration to file SharedConfig.xml.
        """
        # Not used currently
        return self


class Certificates(object):
    """
    Object containing certificates of host and provisioned user.
    """

    def __init__(self, client, xml_text):
        logger.verbose("Load Certificates.xml")
        self.client = client
        self.cert_list = CertList()
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Parse multiple certificates into seperate files.
        """
        xml_doc = parse_doc(xml_text)
        data = findtext(xml_doc, "Data")
        if data is None:
            return

        cryptutil = CryptUtil(conf.get_openssl_cmd())
        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n"
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(p7m_file, p7m_file, data)

        self.client.save_cache(p7m_file, p7m)

        trans_prv_file = os.path.join(conf.get_lib_dir(),
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        pem_file = os.path.join(conf.get_lib_dir(), PEM_FILE_NAME)
        # decrypt certificates
        cryptutil.decrypt_p7m(p7m_file, trans_prv_file, trans_cert_file,
                              pem_file)

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
                    tmp_file = self.write_to_tmp_file(index, 'prv', buf)
                    pub = cryptutil.get_pubkey_from_prv(tmp_file)
                    prvs[pub] = tmp_file
                    buf = []
                    index += 1
                    begin_prv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmp_file = self.write_to_tmp_file(index, 'crt', buf)
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

        for v1_cert in v1_cert_list:
            cert = Cert()
            set_properties("certs", cert, v1_cert)
            self.cert_list.certificates.append(cert)

    def write_to_tmp_file(self, index, suffix, buf):
        file_name = os.path.join(conf.get_lib_dir(),
                                 "{0}.{1}".format(index, suffix))
        self.client.save_cache(file_name, "".join(buf))
        return file_name


class ExtensionsConfig(object):
    """
    parse ExtensionsConfig, downloading and unpacking them to /var/lib/waagent.
    Install if <enabled>true</enabled>, remove if it is set to false.
    """

    def __init__(self, xml_text):
        logger.verbose("Load ExtensionsConfig.xml")
        self.ext_handlers = ExtHandlerList()
        self.vmagent_manifests = VMAgentManifestList()
        self.status_upload_blob = None
        self.status_upload_blob_type = None
        self.artifacts_profile_blob = None
        if xml_text is not None:
            self.parse(xml_text)

    def parse(self, xml_text):
        """
        Write configuration to file ExtensionsConfig.xml.
        """
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
                manifestUri = VMAgentManifestUri(uri=gettext(uri))
                manifest.versionsManifestUris.append(manifestUri)
            self.vmagent_manifests.vmAgentManifests.append(manifest)

        plugins_list = find(xml_doc, "Plugins")
        plugins = findall(plugins_list, "Plugin")
        plugin_settings_list = find(xml_doc, "PluginSettings")
        plugin_settings = findall(plugin_settings_list, "Plugin")

        for plugin in plugins:
            ext_handler = self.parse_plugin(plugin)
            self.ext_handlers.extHandlers.append(ext_handler)
            self.parse_plugin_settings(ext_handler, plugin_settings)

        self.status_upload_blob = findtext(xml_doc, "StatusUploadBlob")
        self.artifacts_profile_blob = findtext(xml_doc, "InVMArtifactsProfileBlob")

        status_upload_node = find(xml_doc, "StatusUploadBlob")
        self.status_upload_blob_type = getattrib(status_upload_node,
                                                 "statusBlobType")
        logger.verbose("Extension config shows status blob type as [{0}]",
                       self.status_upload_blob_type)

    def parse_plugin(self, plugin):
        ext_handler = ExtHandler()
        ext_handler.name = getattrib(plugin, "name")
        ext_handler.properties.version = getattrib(plugin, "version")
        ext_handler.properties.state = getattrib(plugin, "state")

        auto_upgrade = getattrib(plugin, "autoUpgrade")
        if auto_upgrade is not None and auto_upgrade.lower() == "true":
            ext_handler.properties.upgradePolicy = "auto"
        else:
            ext_handler.properties.upgradePolicy = "manual"

        location = getattrib(plugin, "location")
        failover_location = getattrib(plugin, "failoverlocation")
        for uri in [location, failover_location]:
            version_uri = ExtHandlerVersionUri()
            version_uri.uri = uri
            ext_handler.versionUris.append(version_uri)
        return ext_handler

    def parse_plugin_settings(self, ext_handler, plugin_settings):
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

        for plugin_settings_list in runtime_settings["runtimeSettings"]:
            handler_settings = plugin_settings_list["handlerSettings"]
            ext = Extension()
            # There is no "extension name" in wire protocol.
            # Put
            ext.name = ext_handler.name
            ext.sequenceNumber = seqNo
            ext.publicSettings = handler_settings.get("publicSettings")
            ext.protectedSettings = handler_settings.get("protectedSettings")
            thumbprint = handler_settings.get(
                "protectedSettingsCertThumbprint")
            ext.certificateThumbprint = thumbprint
            ext_handler.properties.extensions.append(ext)


class ExtensionManifest(object):
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ExtensionManifest is None")
        logger.verbose("Load ExtensionManifest.xml")
        self.pkg_list = ExtHandlerPackageList()
        self.parse(xml_text)

    def parse(self, xml_text):
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
                pkg_uri = ExtHandlerVersionUri()
                pkg_uri.uri = uri
                pkg.uris.append(pkg_uri)

            pkg.isinternal = isinternal
            self.pkg_list.versions.append(pkg)


# Do not extend this class
class InVMArtifactsProfile(object):
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
    def __init__(self, artifacts_profile):
        if not textutil.is_str_none_or_whitespace(artifacts_profile):
            self.__dict__.update(parse_json(artifacts_profile))

    def is_on_hold(self):
        # hasattr() is not available in Python 2.6
        if 'onHold' in self.__dict__:
            return self.onHold.lower() == 'true'
        return False
