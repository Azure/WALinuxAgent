# Microsoft Azure Linux Agent # pylint: disable=C0302
#
# Copyright 2018 Microsoft Corporation
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
import json
import os
import random
import time
import traceback
import xml.sax.saxutils as saxutils
from datetime import datetime # pylint: disable=ungrouped-imports

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.datacontract import validate_param
from azurelinuxagent.common.event import add_event, add_periodic, WALAEventOperation, EVENTS_DIRECTORY, EventLogger, \
    report_event
from azurelinuxagent.common.exception import ProtocolNotFoundError, \
    ResourceGoneError, ExtensionDownloadError, InvalidContainerError, ProtocolError, HttpError
from azurelinuxagent.common.future import httpclient, bytebuffer, ustr
from azurelinuxagent.common.protocol.extensions_config_retriever import ExtensionsConfigRetriever
from azurelinuxagent.common.protocol.goal_state import GoalState, TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME, \
    ExtensionsConfig, UpdateType
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import DataContract, ExtensionStatus, ExtHandlerPackage, \
    ExtHandlerPackageList, ExtHandlerVersionUri, ProvisionStatus, VMInfo, VMStatus
from azurelinuxagent.common.telemetryevent import TelemetryEventList, GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.utils.archive import StateFlusher
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, \
    findtext, gettext, remove_bom, get_bytes_from_pem, parse_json
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

VERSION_INFO_URI = "http://{0}/?comp=versions"
HEALTH_REPORT_URI = "http://{0}/machine?comp=health"
ROLE_PROP_URI = "http://{0}/machine?comp=roleProperties"
TELEMETRY_URI = "http://{0}/machine?comp=telemetrydata"

ARTIFACTS_PROFILE_BLOB_FILE_NAME = "InVmArtifactsProfileBlob_ft.{0}.json"
WIRE_SERVER_ADDR_FILE_NAME = "WireServer"
GOAL_STATE_FILE_NAME = "GoalState_fa.{0}.xml"
HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
SHARED_CONF_FILE_NAME = "SharedConfig.xml"
REMOTE_ACCESS_FILE_NAME = "RemoteAccess.{0}.xml"
MANIFEST_FILE_NAME = "{0}.{1}.manifest.xml"

PROTOCOL_VERSION = "2012-11-30"
ENDPOINT_FINE_NAME = "WireServer"

HEADER_ETAG = "etag"

SHORT_WAITING_INTERVAL = 1  # 1 second

MAX_EVENT_BUFFER_SIZE = 2 ** 16 - 2 ** 10


class UploadError(HttpError):
    pass



class WireProtocol(DataContract):
    def __init__(self, endpoint):
        if endpoint is None:
            raise ProtocolError("WireProtocol endpoint is None")
        self.client = WireClient(endpoint)

    def detect(self):
        self.client.check_wire_protocol_version()

        trans_prv_file = os.path.join(conf.get_lib_dir(),
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        cryptutil = CryptUtil(conf.get_openssl_cmd())
        cryptutil.gen_transport_cert(trans_prv_file, trans_cert_file)

        # Set the initial goal state
        logger.info('Initializing goal state during protocol detection')
        self.client.update_goal_state(forced=True)

    def update_goal_state(self):
        self.client.update_goal_state()

    def try_update_goal_state(self):
        return self.client.try_update_goal_state()

    def update_host_plugin_from_goal_state(self):
        self.client.update_host_plugin_from_goal_state()

    def get_endpoint(self):
        return self.client.get_endpoint()

    def get_vminfo(self):
        goal_state = self.client.get_goal_state()
        hosting_env = self.client.get_hosting_env()

        vminfo = VMInfo()
        vminfo.subscriptionId = None
        vminfo.vmName = hosting_env.vm_name
        vminfo.tenantName = hosting_env.deployment_name
        vminfo.roleName = hosting_env.role_name
        vminfo.roleInstanceName = goal_state.role_instance_id
        return vminfo

    def get_certs(self):
        certificates = self.client.get_certs()
        return certificates.cert_list

    def get_incarnation(self):
        return self.client.get_goal_state().incarnation

    def get_vmagent_manifests(self):
        goal_state = self.client.get_goal_state()
        ext_conf = self.client.get_ext_conf()
        return ext_conf.vmagent_manifests, goal_state.incarnation

    def get_vmagent_pkgs(self, vmagent_manifest):
        goal_state = self.client.get_goal_state()
        ga_manifest = self.client.get_gafamily_manifest(vmagent_manifest, goal_state)
        valid_pkg_list = ga_manifest.pkg_list
        return valid_pkg_list

    def get_ext_config(self):
        logger.verbose("Get extension handler config")
        ext_conf = self.client.get_ext_conf()
        return ext_conf

    def get_ext_handler_pkgs(self, ext_handler):
        logger.verbose("Get extension handler package")
        man = self.client.get_ext_manifest(ext_handler)
        return man.pkg_list

    def _download_ext_handler_pkg_through_host(self, uri, destination):
        host = self.client.get_host_plugin()
        uri, headers = host.get_artifact_request(uri, host.manifest_uri)
        success = self.client.stream(uri, destination, headers=headers, use_proxy=False)
        return success

    def download_ext_handler_pkg(self, uri, destination, headers=None, use_proxy=True): # pylint: disable=W0613
        direct_func = lambda: self.client.stream(uri, destination, headers=None, use_proxy=True)
        # NOTE: the host_func may be called after refreshing the goal state, be careful about any goal state data
        # in the lambda.
        host_func = lambda: self._download_ext_handler_pkg_through_host(uri, destination)

        try:
            success = self.client.send_request_using_appropriate_channel(direct_func, host_func)
        except Exception:
            success = False

        return success

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

    def report_ext_status(self, ext_handler_name, ext_name, ext_status): # pylint: disable=W0613
        validate_param("ext_status", ext_status, ExtensionStatus)
        self.client.status_blob.set_ext_status(ext_handler_name, ext_status)

    def report_event(self, events):
        validate_param(EVENTS_DIRECTORY, events, TelemetryEventList)
        self.client.report_event(events)

    def upload_logs(self, logs):
        self.client.upload_logs(logs)


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


def _build_health_report(incarnation, container_id, role_instance_id, # pylint: disable=R0913
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


def ga_status_to_guest_info(ga_status):
    """
    Convert VMStatus object to status blob format
    """
    v1_ga_guest_info = {
        "computerName": ga_status.hostname,
        "osName": ga_status.osname,
        "osVersion": ga_status.osversion,
        "version": ga_status.version,
    }
    return v1_ga_guest_info


def ga_status_to_v1(ga_status):
    formatted_msg = {
        'lang': 'en-US',
        'message': ga_status.message
    }
    v1_ga_status = {
        "version": ga_status.version,
        "status": ga_status.status,
        "formattedMessage": formatted_msg
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
    if len(v1_sub_status) != 0: # pylint: disable=len-as-condition
        v1_ext_status['status']['substatus'] = v1_sub_status
    return v1_ext_status


def ext_handler_status_to_v1(handler_status, ext_statuses, timestamp): # pylint: disable=W0613
    v1_handler_status = {
        'handlerVersion': handler_status.version,
        'handlerName': handler_status.name,
        'status': handler_status.status,
        'code': handler_status.code,
        'useExactVersion': True
    }
    if handler_status.message is not None:
        v1_handler_status["formattedMessage"] = {
            "lang": "en-US",
            "message": handler_status.message
        }

    if len(handler_status.extensions) > 0: # pylint: disable=len-as-condition
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


def vm_status_to_v1(vm_status, ext_statuses, extensions_fast_track_enabled):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    v1_supported_features = None
    v1_ga_guest_info = ga_status_to_guest_info(vm_status.vmAgent)
    v1_ga_status = ga_status_to_v1(vm_status.vmAgent)
    v1_handler_status_list = []
    for handler_status in vm_status.vmAgent.extensionHandlers:
        v1_handler_status = ext_handler_status_to_v1(handler_status,
                                                     ext_statuses, timestamp)
        if v1_handler_status is not None:
            v1_handler_status_list.append(v1_handler_status)

    # Inform CRP that we support FastTrack, which allows us to retrieve goal state
    # from the VMArtifactsProfile blob instead of from wire server
    if extensions_fast_track_enabled:
        v1_supported_features = [{'Key': 'FastTrack', 'Value': '1.0'}]

    v1_agg_status = {
        'guestAgentStatus': v1_ga_status,
        'handlerAggregateStatus': v1_handler_status_list
    }
    v1_vm_status = {
        'version': '1.1',
        'timestampUTC': timestamp,
        'aggregateStatus': v1_agg_status,
        'guestOSInfo': v1_ga_guest_info,
        'supportedFeatures': v1_supported_features
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

    def to_json(self, extensions_fast_track_enabled):
        report = vm_status_to_v1(self.vm_status, self.ext_statuses, extensions_fast_track_enabled)
        return json.dumps(report)

    __storage_version__ = "2014-02-14"

    def prepare(self, blob_type, extensions_fast_track_enabled):
        logger.verbose("Prepare status blob")
        self.data = self.to_json(extensions_fast_track_enabled)
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

        except Exception as e: # pylint: disable=C0103
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
    param_format = ustr('<Param Name="{0}" Value={1} T="{2}" />')
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


def event_to_v1_encoded(event, encoding='utf-8'):
    params = ""
    for param in event.parameters:
        params += event_param_to_v1(param)
    event_str = ustr('<Event id="{0}"><![CDATA[{1}]]></Event>').format(event.eventId, params)
    return event_str.encode(encoding)


class WireClient(object): # pylint: disable=R0904

    def __init__(self, endpoint):
        logger.info("Wire server endpoint:{0}", endpoint)
        self._endpoint = endpoint
        self._goal_state = None
        self._last_try_update_goal_state_failed = False
        self._host_plugin = None
        self.vm_artifacts_profile_etag = None
        self.status_blob = StatusBlob(self)
        self.goal_state_flusher = StateFlusher(conf.get_lib_dir())
        self.ext_config_retriever = ExtensionsConfigRetriever(self)

    def get_endpoint(self):
        return self._endpoint

    def call_wireserver(self, http_req, *args, **kwargs):
        try:
            # Never use the HTTP proxy for wireserver
            kwargs['use_proxy'] = False
            resp = http_req(*args, **kwargs)

            if restutil.request_failed(resp):
                msg = "[Wireserver Failed] URI {0} ".format(args[0])
                if resp is not None:
                    msg += " [HTTP Failed] Status Code {0}".format(resp.status)
                raise ProtocolError(msg)

        # If the GoalState is stale, pass along the exception to the caller
        except ResourceGoneError:
            raise

        except Exception as e: # pylint: disable=C0103
            raise ProtocolError("[Wireserver Exception] {0}".format(
                ustr(e)))

        return resp

    def hostgaplugin_supports_fast_track(self):
        if self.vm_artifacts_profile_etag is None:
            return False
        return True

    def decode_config(self, data):
        if data is None:
            return None
        data = remove_bom(data)
        xml_text = ustr(data, encoding='utf-8')
        return xml_text

    def fetch_config(self, uri, headers):
        resp = self.call_wireserver(restutil.http_get,
                                    uri,
                                    headers=headers)
        return self.decode_config(resp.read())

    def fetch_cache(self, local_file):
        if not os.path.isfile(local_file):
            raise ProtocolError("{0} is missing.".format(local_file))
        try:
            return fileutil.read_file(local_file)
        except IOError as e: # pylint: disable=C0103
            raise ProtocolError("Failed to read cache: {0}".format(e))

    def save_cache(self, local_file, data):
        try:
            fileutil.write_file(local_file, data)
        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e, paths=[local_file])
            raise ProtocolError("Failed to write cache: {0}".format(e))

    @staticmethod
    def call_storage_service(http_req, *args, **kwargs):
        # Default to use the configured HTTP proxy
        if not 'use_proxy' in kwargs or kwargs['use_proxy'] is None: # pylint: disable=C0113
            kwargs['use_proxy'] = True

        return http_req(*args, **kwargs)

    def fetch_manifest_through_host(self, uri):
        host = self.get_host_plugin()
        uri, headers = host.get_artifact_request(uri)
        response = self.fetch(uri, headers, use_proxy=False)
        return response

    def fetch_manifest(self, version_uris):
        logger.verbose("Fetch manifest")
        version_uris_shuffled = version_uris
        random.shuffle(version_uris_shuffled)

        for version in version_uris_shuffled:
            # GA expects a location and failoverLocation in ExtensionsConfig, but
            # this is not always the case. See #1147.
            if version.uri is None:
                logger.verbose('The specified manifest URL is empty, ignored.')
                continue

            direct_func = lambda: self.fetch(version.uri) # pylint: disable=W0640
            # NOTE: the host_func may be called after refreshing the goal state, be careful about any goal state data
            # in the lambda.
            host_func = lambda: self.fetch_manifest_through_host(version.uri) # pylint: disable=W0640

            try:
                response = self.send_request_using_appropriate_channel(direct_func, host_func)

                if response:
                    host = self.get_host_plugin()
                    host.update_manifest_uri(version.uri)
                    return response
            except Exception as e: # pylint: disable=C0103
                logger.warn("Exception when fetching manifest. Error: {0}".format(ustr(e)))

        raise ExtensionDownloadError("Failed to fetch manifest from all sources")

    def stream(self, uri, destination, headers=None, use_proxy=None):
        success = False
        logger.verbose("Fetch [{0}] with headers [{1}] to file [{2}]", uri, headers, destination)

        response = self._fetch_response(uri, headers, use_proxy)
        if response is not None:
            chunk_size = 1024 * 1024  # 1MB buffer
            try:
                with open(destination, 'wb', chunk_size) as destination_fh:
                    complete = False
                    while not complete:
                        chunk = response.read(chunk_size)
                        destination_fh.write(chunk)
                        complete = len(chunk) < chunk_size
                success = True
            except Exception as e: # pylint: disable=C0103
                logger.error('Error streaming {0} to {1}: {2}'.format(uri, destination, ustr(e)))

        return success

    def fetch_content_and_etag(self, uri, headers=None, use_proxy=None, decode=True):
        logger.verbose("Fetch [{0}] with headers [{1}]", uri, headers)
        content = None
        etag = None
        not_modified = False
        response = self._fetch_response(uri, headers, use_proxy)
        if response is not None or restutil.request_not_modified(response):
            if restutil.request_not_modified(response):
                not_modified = True
                logger.verbose('Received not-modified response')
            else:
                etag = response.getheader(HEADER_ETAG, None)
                logger.verbose('Received etag of {0}', etag)
                response_content = response.read()
                content = self.decode_config(response_content) if decode else response_content
        return content, etag, not_modified

    def fetch(self, uri, headers=None, use_proxy=None, decode=True):
        logger.verbose("Fetch [{0}] with headers [{1}]", uri, headers)
        content = None
        response = self._fetch_response(uri, headers, use_proxy)
        if response is not None:
            response_content = response.read()
            content = self.decode_config(response_content) if decode else response_content
        return content

    def _fetch_response(self, uri, headers=None, use_proxy=None):
        resp = None
        try:
            resp = self.call_storage_service(
                restutil.http_get,
                uri,
                headers=headers,
                use_proxy=use_proxy)

            host_plugin = self.get_host_plugin()

            if restutil.request_not_modified(resp):
                if self._host_plugin is not None:
                    self._host_plugin.report_fetch_health(uri, source='WireClient')
            elif restutil.request_failed(resp): # pylint: disable=R1720
                error_response = restutil.read_response_error(resp)
                msg = "Fetch failed from [{0}]: {1}".format(uri, error_response)
                logger.warn(msg)

                if host_plugin is not None:
                    host_plugin.report_fetch_health(uri,
                                                    is_healthy=not restutil.request_failed_at_hostplugin(resp),
                                                    source='WireClient',
                                                    response=error_response)
                raise ProtocolError(msg)
            else:
                if host_plugin is not None:
                    host_plugin.report_fetch_health(uri, source='WireClient')

        except (HttpError, ProtocolError, IOError) as e: # pylint: disable=C0103
            logger.verbose("Fetch failed from [{0}]: {1}", uri, e)
            if isinstance(e, ResourceGoneError) or isinstance(e, InvalidContainerError): # pylint: disable=R1701
                raise
        return resp

    # Type of update performed by _update_from_goal_state()
    class _UpdateType(object): # pylint: disable=R0903
        # Update the Host GA Plugin client (Container ID and RoleConfigName)
        HostPlugin = 0
        # Update the full goal state only if the incarnation has changed
        GoalState = 1
        # Update the full goal state unconditionally
        GoalStateForced = 2

    def update_host_plugin_from_goal_state(self):
        """
        Fetches a new goal state and updates the Container ID and Role Config Name of the host plugin client
        """
        self._update_from_goal_state(UpdateType.HostPlugin)

    def update_goal_state(self, forced=False):
        """
        Updates the goal state if the incarnation changed or if 'forced' is True
        """
        self._update_from_goal_state(UpdateType.GoalStateForced if forced else UpdateType.GoalState)

    def try_update_goal_state(self):
        """
        Attempts to update the goal state and returns True on success or False on failure, sending telemetry events about the failures.
        """
        try:
            self.update_goal_state()

            if self._last_try_update_goal_state_failed:
                self._last_try_update_goal_state_failed = False
                message = u"Retrieving the goal state recovered from previous errors"
                add_event(AGENT_NAME, op=WALAEventOperation.FetchGoalState, version=CURRENT_VERSION, is_success=True, message=message, log_event=False)
                logger.info(message)
        except Exception as e: # pylint: disable=C0103
            if not self._last_try_update_goal_state_failed:
                self._last_try_update_goal_state_failed = True
                message = u"An error occurred while retrieving the goal state: {0}".format(ustr(e))
                add_event(AGENT_NAME, op=WALAEventOperation.FetchGoalState, version=CURRENT_VERSION, is_success=False, message=message, log_event=False)
                message = u"An error occurred while retrieving the goal state: {0}".format(ustr(traceback.format_exc()))
                logger.warn(message)
            message = u"Attempts to retrieve the goal state are failing: {0}".format(ustr(e))
            logger.periodic_warn(logger.EVERY_SIX_HOURS, "[PERIODIC] {0}".format(message))
            return False
        return True

    def _update_from_goal_state(self, refresh_type):
        """
        Fetches a new goal state and updates the internal state of the WireClient according to the requested 'refresh_type'
        """
        max_retry = 3

        for retry in range(1, max_retry + 1):
            try:
                if refresh_type == UpdateType.HostPlugin:
                    goal_state = GoalState.fetch_limited_goal_state(self)
                    self._update_host_plugin(goal_state.container_id, goal_state.role_config_name)
                    return

                if self._goal_state is None or refresh_type == UpdateType.GoalStateForced:
                    new_goal_state = GoalState.fetch_full_goal_state(self)
                else:
                    new_goal_state = GoalState.fetch_goal_state(self)
                self._cache_goal_state_and_update_host_plugin(new_goal_state, refresh_type)

                return

            except IOError as e: # pylint: disable=C0103
                logger.warn("IOError processing goal state (attempt {0}/{1}) [{2}]", retry, max_retry, ustr(e))

            except ResourceGoneError:
                logger.info("Goal state is stale, re-fetching (attempt {0}/{1})", retry, max_retry)

            except ProtocolError as e: # pylint: disable=C0103
                logger.verbose("ProtocolError processing goal state (attempt {0}/{1}) [{2}]", retry, max_retry, ustr(e))

            except Exception as e: # pylint: disable=C0103
                logger.verbose("Exception processing goal state (attempt {0}/{1}) [{2}]", retry, max_retry, ustr(e))

        raise ProtocolError("Exceeded max retry updating goal state")

    def _cache_goal_state_and_update_host_plugin(self, new_goal_state, refresh_type):
        # We cache the goal state if one of the following is true
        # 1) We didn't previously have a goal state
        # 2) The incarnation changed
        # 3) The extensions config changed
        # 4) We have an update type of GoalStateForced
        save_goal_state = False
        if self._goal_state is None or new_goal_state.incarnation != self._goal_state.incarnation:
            save_goal_state = True
            self._goal_state = new_goal_state
        elif refresh_type == UpdateType.GoalStateForced:
            save_goal_state = True
            self._goal_state = new_goal_state
        elif new_goal_state.ext_conf is not None and new_goal_state.ext_conf.changed:
            self._goal_state = new_goal_state

        # We save the goal state and update the host plugin only if one of the following is true
        # 1) We didn't previously have a goal state
        # 2) The incarnation changed
        # 3) We have an update type of GoalStateForced
        if save_goal_state:
            self._save_goal_state()
            self._update_host_plugin(new_goal_state.container_id, new_goal_state.role_config_name)

    def _update_host_plugin(self, container_id, role_config_name):
        if self._host_plugin is not None:
            self._host_plugin.update_container_id(container_id)
            self._host_plugin.update_role_config_name(role_config_name)

    def _save_goal_state(self):
        try:
            self.goal_state_flusher.flush(datetime.utcnow())

        except Exception as e: # pylint: disable=C0103
            logger.warn("Failed to save the previous goal state to the history folder: {0}", ustr(e))

        try:
            def save_if_not_none(goal_state_property, file_name):
                file_path = os.path.join(conf.get_lib_dir(), file_name)

                if goal_state_property is not None and goal_state_property.xml_text is not None:
                    self.save_cache(file_path, goal_state_property.xml_text)

            # NOTE: Certificates are saved in Certificate.__init__
            save_if_not_none(self._goal_state, GOAL_STATE_FILE_NAME.format(self._goal_state.incarnation))
            save_if_not_none(self._goal_state.hosting_env, HOSTING_ENV_FILE_NAME)
            save_if_not_none(self._goal_state.shared_conf, SHARED_CONF_FILE_NAME)
            save_if_not_none(self._goal_state.ext_conf, self._goal_state.ext_conf.get_ext_config_file_name())
            save_if_not_none(self._goal_state.remote_access, REMOTE_ACCESS_FILE_NAME.format(self._goal_state.incarnation))

        except Exception as e: # pylint: disable=C0103
            logger.warn("Failed to save the goal state to disk: {0}", ustr(e))

    def _set_host_plugin(self, new_host_plugin):
        if new_host_plugin is None:
            logger.warn("Setting empty Host Plugin object!")
        self._host_plugin = new_host_plugin

    def get_goal_state(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch goal state before initialization!")
        return self._goal_state

    def get_hosting_env(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Hosting Environment before initialization!")
        return self._goal_state.hosting_env

    def get_shared_conf(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Shared Conf before initialization!")
        return self._goal_state.shared_conf

    def get_certs(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Certificates before initialization!")
        return self._goal_state.certs

    def get_ext_conf(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Extension Conf before initialization!")
        return self._goal_state.ext_conf

    def get_ext_manifest(self, ext_handler):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Extension Manifest before initialization!")

        local_file = MANIFEST_FILE_NAME.format(ext_handler.name, self.get_goal_state().incarnation)
        local_file = os.path.join(conf.get_lib_dir(), local_file)

        try:
            xml_text = self.fetch_manifest(ext_handler.versionUris)
            self.save_cache(local_file, xml_text)
            return ExtensionManifest(xml_text)
        except Exception as e: # pylint: disable=C0103
            raise ExtensionDownloadError("Failed to retrieve extension manifest. Error: {0}".format(ustr(e)))

    def get_remote_access(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Remote Access before initialization!")
        return self._goal_state.remote_access

    def get_gafamily_manifest(self, vmagent_manifest, goal_state):
        local_file = MANIFEST_FILE_NAME.format(vmagent_manifest.family, goal_state.incarnation)
        local_file = os.path.join(conf.get_lib_dir(), local_file)

        try:
            xml_text = self.fetch_manifest(vmagent_manifest.versionsManifestUris)
            fileutil.write_file(local_file, xml_text)
            return ExtensionManifest(xml_text)
        except Exception as e: # pylint: disable=C0103
            raise ProtocolError("Failed to retrieve GAFamily manifest. Error: {0}".format(ustr(e)))

    def check_wire_protocol_version(self):
        uri = VERSION_INFO_URI.format(self.get_endpoint())
        version_info_xml = self.fetch_config(uri, None)
        version_info = VersionInfo(version_info_xml)

        preferred = version_info.get_preferred()
        if PROTOCOL_VERSION == preferred:
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
        elif PROTOCOL_VERSION in version_info.get_supported():
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
            logger.info("Server preferred version:{0}", preferred)
        else:
            error = ("Agent supported wire protocol version: {0} was not "
                     "advised by Fabric.").format(PROTOCOL_VERSION)
            raise ProtocolNotFoundError(error)

    def call_hostplugin_with_container_check(self, host_func, uses_etag):
        ret = None
        etag = None
        not_modified = False         # Corresponds to a 304 NOT MODIFIED response from the server
        try:
            if uses_etag:
                ret, etag, not_modified = host_func()
            else:
                ret = host_func()
        except (ResourceGoneError, InvalidContainerError) as e: # pylint: disable=C0103
            host_plugin = self.get_host_plugin()
            old_container_id = host_plugin.container_id
            old_role_config_name = host_plugin.role_config_name

            msg = "[PERIODIC] Request failed with the current host plugin configuration. " \
                  "ContainerId: {0}, role config file: {1}. Fetching new goal state and retrying the call." \
                  "Error: {2}".format(old_container_id, old_role_config_name, ustr(e))
            logger.periodic_info(logger.EVERY_SIX_HOURS, msg)

            self.update_host_plugin_from_goal_state()

            new_container_id = host_plugin.container_id
            new_role_config_name = host_plugin.role_config_name
            msg = "[PERIODIC] Host plugin reconfigured with new parameters. " \
                  "ContainerId: {0}, role config file: {1}.".format(new_container_id, new_role_config_name)
            logger.periodic_info(logger.EVERY_SIX_HOURS, msg)

            try:
                if uses_etag:
                    ret, etag, not_modified = host_func()
                else:
                    ret = host_func()

                if ret or not not_modified:
                    msg = "[PERIODIC] Request succeeded using the host plugin channel after goal state refresh. " \
                          "ContainerId changed from {0} to {1}, " \
                          "role config file changed from {2} to {3}.".format(old_container_id, new_container_id,
                                                                             old_role_config_name, new_role_config_name)
                    add_periodic(delta=logger.EVERY_SIX_HOURS,
                                 name=AGENT_NAME,
                                 version=CURRENT_VERSION,
                                 op=WALAEventOperation.HostPlugin,
                                 is_success=True,
                                 message=msg,
                                 log_event=True)

            except (ResourceGoneError, InvalidContainerError) as e: # pylint: disable=C0103
                msg = "[PERIODIC] Request failed using the host plugin channel after goal state refresh. " \
                      "ContainerId changed from {0} to {1}, role config file changed from {2} to {3}. " \
                      "Exception type: {4}.".format(old_container_id, new_container_id, old_role_config_name,
                                                    new_role_config_name, type(e).__name__)
                add_periodic(delta=logger.EVERY_SIX_HOURS,
                             name=AGENT_NAME,
                             version=CURRENT_VERSION,
                             op=WALAEventOperation.HostPlugin,
                             is_success=False,
                             message=msg,
                             log_event=True)
                raise
        return ret, etag, not_modified

    def send_request_hostplugin_first(self, direct_func, host_func):
        # For certain calls we want them to go through the HostGAPlugin first, since it
        # supports the If-None-Match header that reduces how often we need to parse

        # note that this method requires a lambda that returns three values
        ret, etag, not_modified = self.call_hostplugin_with_container_check(host_func, uses_etag=True)
        if ret or not_modified:
            return ret, etag

        try:
            ret = direct_func()
        except (ResourceGoneError, InvalidContainerError) as e:
            logger.periodic_info(logger.EVERY_HOUR, "Request failed with direct. Error: {0}".format(ustr(e)))

        return ret, etag

    def send_request_using_appropriate_channel(self, direct_func, host_func):
        # A wrapper method for all function calls that send HTTP requests. The purpose of the method is to
        # define which channel to use, direct or through the host plugin. For the host plugin channel,
        # also implement a retry mechanism.

        # By default, the direct channel is the default channel. If that is the case, try getting a response
        # through that channel. On failure, fall back to the host plugin channel.

        # When using the host plugin channel, regardless if it's set as default or not, try sending the request first.
        # On specific failures that indicate a stale goal state (such as resource gone or invalid container parameter),
        # refresh the goal state and try again. If successful, set the host plugin channel as default. If failed,
        # raise the exception.

        # NOTE: direct_func and host_func are passed as lambdas. Be careful about capturing goal state data in them as
        # they will not be refreshed even if a goal state refresh is called before retrying the host_func.

        if not HostPluginProtocol.is_default_channel():
            ret = None
            try:
                ret = direct_func()

                # Different direct channel functions report failure in different ways: by returning None, False,
                # or raising ResourceGone or InvalidContainer exceptions.
                if not ret:
                    logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel, "
                                                            "switching to host plugin.")
            except (ResourceGoneError, InvalidContainerError) as e:
                logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel, "
                                                        "switching to host plugin. Error: {0}".format(ustr(e)))

            if ret:
                return ret
        else:
            logger.periodic_info(logger.EVERY_HALF_DAY, "[PERIODIC] Using host plugin as default channel.")

        ret, _, _ = self.call_hostplugin_with_container_check(host_func, uses_etag=False)

        return ret

    def send_request_using_appropriate_channel(self, direct_func, host_func):
        # A wrapper method for all function calls that send HTTP requests. The purpose of the method is to
        # define which channel to use, direct or through the host plugin. For the host plugin channel,
        # also implement a retry mechanism.

        # By default, the direct channel is the default channel. If that is the case, try getting a response
        # through that channel. On failure, fall back to the host plugin channel.

        # When using the host plugin channel, regardless if it's set as default or not, try sending the request first.
        # On specific failures that indicate a stale goal state (such as resource gone or invalid container parameter),
        # refresh the goal state and try again. If successful, set the host plugin channel as default. If failed,
        # raise the exception.

        # NOTE: direct_func and host_func are passed as lambdas. Be careful about capturing goal state data in them as
        # they will not be refreshed even if a goal state refresh is called before retrying the host_func.

        if not HostPluginProtocol.is_default_channel():
            ret = None
            try:
                ret = direct_func()

                # Different direct channel functions report failure in different ways: by returning None, False,
                # or raising ResourceGone or InvalidContainer exceptions.
                if not ret:
                    logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel, "
                                                            "switching to host plugin.")
            except (ResourceGoneError, InvalidContainerError) as e: # pylint: disable=C0103
                logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel, "
                                                        "switching to host plugin. Error: {0}".format(ustr(e)))

            if ret:
                return ret
        else:
            logger.periodic_info(logger.EVERY_HALF_DAY, "[PERIODIC] Using host plugin as default channel.")

        ret = self._call_hostplugin_with_container_check(host_func)

        if not HostPluginProtocol.is_default_channel():
            logger.info("Setting host plugin as default channel from now on. "
                        "Restart the agent to reset the default channel.")
            HostPluginProtocol.set_default_channel(True)

        return ret

    def get_extensions_fast_track_enabled(self):
        # Eventually we'll need to generalize this method to write all features
        # but for now we only have one
        fast_track_enabled = False
        if conf.get_extensions_fast_track_enabled():
            if self.hostgaplugin_supports_fast_track():
                logger.periodic_info(logger.EVERY_DAY, "FastTrack enabled because HostGAPlugin supports it")
                fast_track_enabled = True
            else:
                logger.periodic_info(logger.EVERY_DAY, "FastTrack not enabled because HostGAPlugin doesn't support it")
        else:
            logger.periodic_info(logger.EVERY_DAY, "FastTrack disabled in config")

        return fast_track_enabled

    def upload_status_blob(self):
        if self.ext_config_retriever.status_upload_blob_url is None:
            # the status upload blob is in ExtensionsConfig so force a full goal state refresh
            self.update_goal_state(forced=True)

        if self.ext_config_retriever.status_upload_blob_url is None:
            raise ProtocolNotFoundError("Status upload uri is missing")

        blob_type = self.ext_config_retriever.status_upload_blob_type
        if blob_type not in ["BlockBlob", "PageBlob"]:
            blob_type = "BlockBlob"
            logger.verbose("Status Blob type is unspecified, assuming BlockBlob")

        try:
            self.status_blob.prepare(blob_type, self.get_extensions_fast_track_enabled())
        except Exception as e: # pylint: disable=C0103
            raise ProtocolError("Exception creating status blob: {0}", ustr(e))

        # Swap the order of use for the HostPlugin vs. the "direct" route.
        # Prefer the use of HostPlugin. If HostPlugin fails fall back to the
        # direct route.
        #
        # The code previously preferred the "direct" route always, and only fell back
        # to the HostPlugin *if* there was an error. We would like to move to
        # the HostPlugin for all traffic, but this is a big change.  We would like
        # to see how this behaves at scale, and have a fallback should things go
        # wrong. This is why we try HostPlugin then direct.
        try:
            host = self.get_host_plugin()
            host.put_vm_status(self.status_blob, self.ext_config_retriever.status_upload_blob_url,
                               self.ext_config_retriever.status_upload_blob_type)
            return
        except ResourceGoneError:
            # refresh the host plugin client and try again on the next iteration of the main loop
            self.update_host_plugin_from_goal_state()
            return
        except Exception as e: # pylint: disable=C0103
            # for all other errors, fall back to direct
            msg = "Falling back to direct upload: {0}".format(ustr(e))
            self.report_status_event(msg, is_success=True)

        try:
            if self.status_blob.upload(self.ext_config_retriever.status_upload_blob_url):
                return
        except Exception as e: # pylint: disable=C0103
            msg = "Exception uploading status blob: {0}".format(ustr(e))
            self.report_status_event(msg, is_success=False)

        raise ProtocolError("Failed to upload status blob via either channel")

    def report_role_prop(self, thumbprint):
        goal_state = self.get_goal_state()
        role_prop = _build_role_properties(goal_state.container_id,
                                           goal_state.role_instance_id,
                                           thumbprint)
        role_prop = role_prop.encode("utf-8")
        role_prop_uri = ROLE_PROP_URI.format(self.get_endpoint())
        headers = self.get_header_for_xml_content()
        try:
            resp = self.call_wireserver(restutil.http_post,
                                        role_prop_uri,
                                        role_prop,
                                        headers=headers)
        except HttpError as e: # pylint: disable=C0103
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
        health_report_uri = HEALTH_REPORT_URI.format(self.get_endpoint())
        headers = self.get_header_for_xml_content()
        try:
            # 30 retries with 10s sleep gives ~5min for wireserver updates;
            # this is retried 3 times with 15s sleep before throwing a
            # ProtocolError, for a total of ~15min.
            resp = self.call_wireserver(restutil.http_post,
                                        health_report_uri,
                                        health_report,
                                        headers=headers,
                                        max_retry=30,
                                        retry_delay=15)
        except HttpError as e: # pylint: disable=C0103
            raise ProtocolError((u"Failed to send provision status: "
                                 u"{0}").format(e))
        if restutil.request_failed(resp):
            raise ProtocolError((u"Failed to send provision status: "
                                 u",{0}: {1}").format(resp.status,
                                                      resp.read()))

    def send_encoded_event(self, provider_id, event_str, encoding='utf-8'):
        uri = TELEMETRY_URI.format(self.get_endpoint())
        data_format_header = ustr('<?xml version="1.0"?><TelemetryData version="1.0"><Provider id="{0}">').format(
            provider_id).encode(encoding)
        data_format_footer = ustr('</Provider></TelemetryData>').encode(encoding)
        # Event string should already be encoded by the time it gets here, to avoid double encoding, dividing it into parts.
        data = data_format_header + event_str + data_format_footer
        try:
            header = self.get_header_for_xml_content()
            # NOTE: The call to wireserver requests utf-8 encoding in the headers, but the body should not
            #       be encoded: some nodes in the telemetry pipeline do not support utf-8 encoding.
            resp = self.call_wireserver(restutil.http_post, uri, data, header)
        except HttpError as e: # pylint: disable=C0103
            raise ProtocolError("Failed to send events:{0}".format(e))

        if restutil.request_failed(resp):
            logger.verbose(resp.read())
            raise ProtocolError(
                "Failed to send events:{0}".format(resp.status))

    def report_event(self, event_list):
        max_send_errors_to_report = 5
        buf = {}
        events_per_request = 0
        unicode_error_count, unicode_errors = 0, []
        event_report_error_count, event_report_errors = 0, []

        # Group events by providerId
        for event in event_list.events:
            try:
                if event.providerId not in buf:
                    buf[event.providerId] = b''
                event_str = event_to_v1_encoded(event)
                if len(event_str) >= MAX_EVENT_BUFFER_SIZE:
                    details_of_event = [ustr(x.name) + ":" + ustr(x.value) for x in event.parameters if x.name in
                                        [GuestAgentExtensionEventsSchema.Name, GuestAgentExtensionEventsSchema.Version,
                                         GuestAgentExtensionEventsSchema.Operation,
                                         GuestAgentExtensionEventsSchema.OperationSuccess]]
                    logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                         "Single event too large: {0}, with the length: {1} more than the limit({2})"
                                         .format(str(details_of_event), len(event_str), MAX_EVENT_BUFFER_SIZE))
                    continue
                if len(buf[event.providerId] + event_str) >= MAX_EVENT_BUFFER_SIZE:
                    self.send_encoded_event(event.providerId, buf[event.providerId])
                    buf[event.providerId] = b''
                    logger.verbose("No of events this request = {0}".format(events_per_request))
                    events_per_request = 0
                buf[event.providerId] = buf[event.providerId] + event_str
                events_per_request += 1
            except UnicodeError as e: # pylint: disable=C0103
                unicode_error_count += 1
                if len(unicode_errors) < max_send_errors_to_report:
                    unicode_errors.append(ustr(e))
            except Exception as e: # pylint: disable=C0103
                event_report_error_count += 1
                if len(event_report_errors) < max_send_errors_to_report:
                    event_report_errors.append(ustr(e))

        EventLogger.report_dropped_events_error(event_report_error_count, event_report_errors,
                                                WALAEventOperation.CollectEventErrors, max_send_errors_to_report)
        EventLogger.report_dropped_events_error(unicode_error_count, unicode_errors,
                                                WALAEventOperation.CollectEventUnicodeErrors,
                                                max_send_errors_to_report)

        # Send out all events left in buffer.
        for provider_id in list(buf.keys()):
            if len(buf[provider_id]) > 0: # pylint: disable=len-as-condition
                logger.verbose("No of events this request = {0}".format(events_per_request))
                self.send_encoded_event(provider_id, buf[provider_id])

    def report_status_event(self, message, is_success):
        report_event(op=WALAEventOperation.ReportStatus,
                     is_success=is_success,
                     message=message,
                     log_event=not is_success)

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

    def get_host_plugin(self):
        if self._host_plugin is None:
            goal_state = GoalState.fetch_limited_goal_state(self)
            self._set_host_plugin(HostPluginProtocol(self.get_endpoint(),
                                                     goal_state.container_id,
                                                     goal_state.role_config_name))
        return self._host_plugin

    def get_artifacts_profile_through_host(self, blob, etag=None):
        host = self.get_host_plugin()
        uri, headers = host.get_artifact_request(blob, etag=etag)
        profile, etag, not_modified = self.fetch_content_and_etag(uri, headers, use_proxy=False)
        return profile, etag, not_modified

    def get_artifacts_profile(self, artifacts_profile_blob_url):
        artifacts_profile = None

        if artifacts_profile_blob_url is not None:
            direct_func = lambda: self.fetch(artifacts_profile_blob_url)
            # NOTE: the host_func may be called after refreshing the goal state, be careful about any goal state data
            # in the lambda.
            host_func = lambda: self.get_artifacts_profile_through_host(
                artifacts_profile_blob_url, self.vm_artifacts_profile_etag)

            logger.verbose("Retrieving the artifacts profile")

            try:
                profile, etag = self.send_request_hostplugin_first(direct_func, host_func)
            except Exception as e: # pylint: disable=C0103
                logger.warn("Exception retrieving artifacts profile: {0}".format(ustr(e)))
                return None

            if not textutil.is_str_empty(profile):
                logger.verbose("Artifacts profile downloaded")
                try:
                    artifacts_profile = InVMArtifactsProfile(profile)
                except Exception:
                    logger.warn("Could not parse artifacts profile blob")
                    msg = "Content: [{0}]".format(profile)
                    logger.verbose(msg)

                    report_event(op=WALAEventOperation.ArtifactsProfileBlob,
                                 is_success=False,
                                 message=msg,
                                 log_event=False)

                try:
                    file_name = ARTIFACTS_PROFILE_BLOB_FILE_NAME.format(artifacts_profile.get_sequence_number())
                    file_path = os.path.join(conf.get_lib_dir(), file_name)
                    self.save_cache(file_path, profile)
                except Exception as e:
                    logger.warn("Could not save artifacts profile blob to disk due to: {0}", ustr(e))
            if etag is not None:
                logger.info("Received a new etag for the VMArtifactsProfile blob: {0}", etag)
                self.vm_artifacts_profile_etag = etag

        return artifacts_profile

    def upload_logs(self, content):
        host_func = lambda: self._upload_logs_through_host(content)
        return self._call_hostplugin_with_container_check(host_func)

    def _upload_logs_through_host(self, content):
        host = self.get_host_plugin()
        return host.put_vm_log(content)


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


class ExtensionManifest(object): # pylint: disable=R0903
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
                pkg_uri = ExtHandlerVersionUri()
                pkg_uri.uri = uri
                pkg.uris.append(pkg_uri)

            pkg.isinternal = isinternal
            self.pkg_list.versions.append(pkg)


# Do not extend this class
class InVMArtifactsProfile(object): # pylint: disable=R0903
    """
    deserialized json string of InVMArtifactsProfile.
    It is expected to contain the following fields:
    * inVMArtifactsProfileBlobSeqNo
    * profileId (optional)
    * onHold (optional)
    * certificateThumbprint (optional)
    * encryptedHealthChecks (optional)
    * encryptedApplicationProfile (optional)
    * extensionGoalStates (optional)
    """

    def __init__(self, artifacts_profile):
        if not textutil.is_str_empty(artifacts_profile):
            self.__dict__.update(parse_json(artifacts_profile))

    def is_on_hold(self):
        # hasattr() is not available in Python 2.6
        if 'onHold' in self.__dict__:
            return str(self.onHold).lower() == 'true' # pylint: disable=E1101
        return False

    def get_sequence_number(self):
        if 'inVMArtifactsProfileBlobSeqNo' in self.__dict__:
            return int(self.inVMArtifactsProfileBlobSeqNo)
        return None

    def get_created_on_ticks(self):
        if 'createdOnTicks' in self.__dict__:
            return int(self.createdOnTicks)
        return None

    def has_extensions(self):
        if 'extensionGoalStates' in self.__dict__:
            if len(self.extensionGoalStates) > 0:
                return True
        return False

    def transform_to_extensions_config(self, flush_func=None):
        """
        We need to convert the json from the InVmArtifactsProfile blob to the following
        format for the ExtensionsConfig:
        <Extensions version="1.0.0.0" goalStateIncarnation="9" fastTrack="true">
        <Plugins>
            <Plugin name="MyExtension.Blah" version="1.0.0"
                    location="http://somewhere.xml"
                    config="" state="enabled" autoUpgrade="false"
                    failoverlocation="http://somewherelese.xml"
                    runAsStartupTask="false" isJson="true"/>
            <Plugin name="Microsoft.Flipperdoodle" version="1.0.0"
                    location="https://somewhere_two.xml"
                    state="enabled" autoUpgrade="true"
                    failoverlocation="https://somewhereelse_two.xml"
                    runAsStartupTask="false" isJson="true" useExactVersion="false"/>
        </Plugins>
        <PluginSettings>
            <Plugin name="MyExtension.Blah" version="1.0.0">
                <RuntimeSettings seqNo="0">{"runtimeSettings":[{"handlerSettings":{"protectedSettingsCertThumbprint":"4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3","protectedSettings":"MIICWgYJK","publicSettings":{"foo":"bar"}}}]}</RuntimeSettings>
            </Plugin>
            <Plugin name="Microsoft.Flipperdoodle" version="1.0.0">
                <RuntimeSettings seqNo="0">{"runtimeSettings":[{"handlerSettings":{"protectedSettingsCertThumbprint":"4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3","protectedSettings":"MIICWgYJK","publicSettings":{"foo":"bar"}}}]}</RuntimeSettings>
            </Plugin>
        </PluginSettings>
        <StatusUploadBlob statusBlobType="BlockBlob">https://putblobhere</StatusUploadBlob>
        </Extensions>
        """
        if 'extensionGoalStates' in self.__dict__:
            import xml.etree.ElementTree as xml
            root = xml.Element("Extensions")
            root.set('version', '1.0.0.0')
            root.set('goalStateIncarnation', str(self.inVMArtifactsProfileBlobSeqNo))
            root.set('fastTrack', 'true')

            # Some properties such as state are required and will generate an exception if not there
            # Others such as autoUpgrade are optional so we'll check first
            plugins = xml.SubElement(root, 'Plugins')
            for extensionGoalState in self.extensionGoalStates:
                plugin = xml.SubElement(plugins, 'Plugin')
                plugin.set('name', extensionGoalState['name'])
                plugin.set('version', extensionGoalState['version'])
                plugin.set('location', extensionGoalState['location'])
                plugin.set('state', extensionGoalState['state'])
                plugin.set('autoUpgrade', str(extensionGoalState.get('autoUpgrade')))
                plugin.set('failoverlocation', str(extensionGoalState.get('failoverlocation')))
                plugin.set('runAsStartupTask', str(extensionGoalState.get('runAsStartupTask')))
                plugin.set('isJson', 'true')
                plugin.set('useExactVersion', str(extensionGoalState.get('useExactVersion')))

            plugin_settings = xml.SubElement(root, 'PluginSettings')
            for extensionGoalState in self.extensionGoalStates:
                plugin = xml.SubElement(plugin_settings, 'Plugin')
                plugin.set('name', extensionGoalState['name'])
                plugin.set('version', extensionGoalState['version'])
                runtime_settings = xml.SubElement(plugin, 'RuntimeSettings')
                runtime_settings.set('seqNo', str(extensionGoalState['settingsSeqNo']))

                # CRP may send multiple settings but this agent only supports one
                settings = extensionGoalState.get('settings')
                if settings is not None and len(settings) > 0:
                    handler_settings = settings[0]
                    json_settings = json.dumps({"runtimeSettings": [{"handlerSettings": handler_settings}]})
                    runtime_settings.text = json_settings

                    # In this agent, we pay attention to only the dependencyLevel for dependencies
                    if extensionGoalState.get('dependsOn') is not None:
                        depends_on = xml.SubElement(runtime_settings, 'DependsOn')
                        self._set_depends_on(depends_on, extensionGoalState)

            config_xml = xml.tostring(root).decode()
            if flush_func is not None:
                flush_func(datetime.utcnow())
            extensions_config = ExtensionsConfig(config_xml)

            return extensions_config
        return None

    def _set_depends_on(self, depends_on, extensionGoalState):
        # dependsOn is a list, so we need to take the highest dependencyLevel of any of them
        set_dependency_level = 0
        ext_depends_on = extensionGoalState.get('dependsOn')
        if ext_depends_on is not None:
            for dependency in ext_depends_on:
                dependency_level = dependency.get('dependencyLevel')
                if dependency_level is not None and dependency_level > set_dependency_level:
                    set_dependency_level = dependency_level
            depends_on.set('dependencyLevel', str(set_dependency_level))