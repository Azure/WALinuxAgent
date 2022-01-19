# Microsoft Azure Linux Agent
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

import json
import os
import random
import time
import uuid
import xml.sax.saxutils as saxutils
from collections import defaultdict
from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_crp
from azurelinuxagent.common.datacontract import validate_param
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_event, \
    CollectOrReportEventDebugInfo, add_periodic
from azurelinuxagent.common.exception import ProtocolNotFoundError, \
    ResourceGoneError, ExtensionDownloadError, InvalidContainerError, ProtocolError, HttpError
from azurelinuxagent.common.future import httpclient, bytebuffer, ustr
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.goal_state import GoalState, TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import DataContract, ExtHandlerPackage, \
    ExtHandlerPackageList, ProvisionStatus, VMInfo, VMStatus
from azurelinuxagent.common.telemetryevent import GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.utils.archive import StateFlusher
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, \
    findtext, gettext, remove_bom, get_bytes_from_pem, parse_json
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

VERSION_INFO_URI = "http://{0}/?comp=versions"
HEALTH_REPORT_URI = "http://{0}/machine?comp=health"
ROLE_PROP_URI = "http://{0}/machine?comp=roleProperties"
TELEMETRY_URI = "http://{0}/machine?comp=telemetrydata"

WIRE_SERVER_ADDR_FILE_NAME = "WireServer"
INCARNATION_FILE_NAME = "Incarnation"
GOAL_STATE_FILE_NAME = "GoalState.{0}.xml"
VM_SETTINGS_FILE_NAME = "VmSettings.{0}.json"
HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
SHARED_CONF_FILE_NAME = "SharedConfig.xml"
REMOTE_ACCESS_FILE_NAME = "RemoteAccess.{0}.xml"
EXT_CONF_FILE_NAME = "ExtensionsConfig.{0}.xml"
MANIFEST_FILE_NAME = "{0}.{1}.manifest.xml"

PROTOCOL_VERSION = "2012-11-30"
ENDPOINT_FINE_NAME = "WireServer"

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

        # Initialize the goal state, including all the inner properties
        logger.info('Initializing goal state during protocol detection')
        self.client.update_goal_state(force_update=True)

    def update_goal_state(self):
        self.client.update_goal_state()

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
        ext_conf = self.client.get_extensions_goal_state()
        return ext_conf.agent_manifests, goal_state.incarnation

    def get_vmagent_pkgs(self, vmagent_manifest):
        goal_state = self.client.get_goal_state()
        ga_manifest = self.client.fetch_gafamily_manifest(vmagent_manifest, goal_state)
        valid_pkg_list = ga_manifest.pkg_list
        return valid_pkg_list

    def get_ext_handler_pkgs(self, ext_handler):
        logger.verbose("Get extension handler package")
        man = self.client.get_ext_manifest(ext_handler)
        return man.pkg_list

    def get_extensions_goal_state(self):
        return self.client.get_extensions_goal_state()

    def _download_ext_handler_pkg_through_host(self, uri, destination):
        host = self.client.get_host_plugin()
        uri, headers = host.get_artifact_request(uri, host.manifest_uri)
        success = self.client.stream(uri, destination, headers=headers, use_proxy=False, max_retry=1)
        return success

    def download_ext_handler_pkg(self, uri, destination, headers=None, use_proxy=True):  # pylint: disable=W0613
        direct_func = lambda: self.client.stream(uri, destination, headers=None, use_proxy=True, max_retry=1)
        # NOTE: the host_func may be called after refreshing the goal state, be careful about any goal state data
        # in the lambda.
        host_func = lambda: self._download_ext_handler_pkg_through_host(uri, destination)

        try:
            success = self.client.send_request_using_appropriate_channel(direct_func, host_func) is not None
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

    def report_event(self, events_iterator):
        self.client.report_event(events_iterator)

    def upload_logs(self, logs):
        self.client.upload_logs(logs)

    def get_status_blob_data(self):
        return self.client.status_blob.data


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
    # The max description that can be sent to WireServer is 4096 bytes.
    # Exceeding this max can result in a failure to report health.
    # To keep this simple, we will keep a 10% buffer and trim before
    # encoding the description.
    if description:
        max_chars_before_encoding = 3686
        len_before_trim = len(description)
        description = description[:max_chars_before_encoding]
        trimmed_char_count = len_before_trim - len(description)
        if trimmed_char_count > 0:
            logger.info(
                'Trimmed health report description by {0} characters'.format(
                    trimmed_char_count
                )
            )

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


def __get_formatted_msg_for_status_reporting(msg, lang="en-US"):
    return {
        'lang': lang,
        'message': msg
    }


def _get_utc_timestamp_for_status_reporting(time_format="%Y-%m-%dT%H:%M:%SZ", timestamp=None):
    timestamp = time.gmtime() if timestamp is None else timestamp
    return time.strftime(time_format, timestamp)


def ga_status_to_v1(ga_status):
    v1_ga_status = {
        "version": ga_status.version,
        "status": ga_status.status,
        "formattedMessage": __get_formatted_msg_for_status_reporting(ga_status.message)
    }

    if ga_status.update_status is not None:
        v1_ga_status["updateStatus"] = get_ga_update_status_to_v1(ga_status.update_status)

    return v1_ga_status


def get_ga_update_status_to_v1(update_status):
    v1_ga_update_status = {
        "expectedVersion": update_status.expected_version,
        "status": update_status.status,
        "code": update_status.code,
        "formattedMessage": __get_formatted_msg_for_status_reporting(update_status.message)
    }
    return v1_ga_update_status


def ext_substatus_to_v1(sub_status_list):
    status_list = []
    for substatus in sub_status_list:
        status = {
            "name": substatus.name,
            "status": substatus.status,
            "code": substatus.code,
            "formattedMessage": __get_formatted_msg_for_status_reporting(substatus.message)
        }
        status_list.append(status)
    return status_list


def ext_status_to_v1(ext_status):
    if ext_status is None:
        return None
    timestamp = _get_utc_timestamp_for_status_reporting()
    v1_sub_status = ext_substatus_to_v1(ext_status.substatusList)
    v1_ext_status = {
        "status": {
            "name": ext_status.name,
            "configurationAppliedTime": ext_status.configurationAppliedTime,
            "operation": ext_status.operation,
            "status": ext_status.status,
            "code": ext_status.code,
            "formattedMessage": __get_formatted_msg_for_status_reporting(ext_status.message)
        },
        "version": 1.0,
        "timestampUTC": timestamp
    }
    if len(v1_sub_status) != 0:
        v1_ext_status['status']['substatus'] = v1_sub_status
    return v1_ext_status


def ext_handler_status_to_v1(ext_handler_status):
    v1_handler_status = {
        'handlerVersion': ext_handler_status.version,
        'handlerName': ext_handler_status.name,
        'status': ext_handler_status.status,
        'code': ext_handler_status.code,
        'useExactVersion': True
    }
    if ext_handler_status.message is not None:
        v1_handler_status["formattedMessage"] = __get_formatted_msg_for_status_reporting(ext_handler_status.message)

    v1_ext_status = ext_status_to_v1(ext_handler_status.extension_status)
    if ext_handler_status.extension_status is not None and v1_ext_status is not None:
        v1_handler_status["runtimeSettingsStatus"] = {
            'settingsStatus': v1_ext_status,
            'sequenceNumber': ext_handler_status.extension_status.sequenceNumber
        }

        # Add extension name if Handler supports MultiConfig
        if ext_handler_status.supports_multi_config:
            v1_handler_status["runtimeSettingsStatus"]["extensionName"] = ext_handler_status.extension_status.name

    return v1_handler_status


def vm_artifacts_aggregate_status_to_v1(vm_artifacts_aggregate_status):
    gs_aggregate_status = vm_artifacts_aggregate_status.goal_state_aggregate_status
    if gs_aggregate_status is None:
        return None

    v1_goal_state_aggregate_status = {
        "formattedMessage": __get_formatted_msg_for_status_reporting(gs_aggregate_status.message),
        "timestampUTC": _get_utc_timestamp_for_status_reporting(timestamp=gs_aggregate_status.processed_time),
        "inSvdSeqNo": gs_aggregate_status.in_svd_seq_no,
        "status": gs_aggregate_status.status,
        "code": gs_aggregate_status.code
    }

    v1_artifact_aggregate_status = {
        "goalStateAggregateStatus": v1_goal_state_aggregate_status
    }
    return v1_artifact_aggregate_status


def vm_status_to_v1(vm_status):
    timestamp = _get_utc_timestamp_for_status_reporting()

    v1_ga_guest_info = ga_status_to_guest_info(vm_status.vmAgent)
    v1_ga_status = ga_status_to_v1(vm_status.vmAgent)
    v1_vm_artifact_aggregate_status = vm_artifacts_aggregate_status_to_v1(
        vm_status.vmAgent.vm_artifacts_aggregate_status)
    v1_handler_status_list = []
    for handler_status in vm_status.vmAgent.extensionHandlers:
        v1_handler_status_list.append(ext_handler_status_to_v1(handler_status))

    v1_agg_status = {
        'guestAgentStatus': v1_ga_status,
        'handlerAggregateStatus': v1_handler_status_list
    }

    if v1_vm_artifact_aggregate_status is not None:
        v1_agg_status['vmArtifactsAggregateStatus'] = v1_vm_artifact_aggregate_status

    v1_vm_status = {
        'version': '1.1',
        'timestampUTC': timestamp,
        'aggregateStatus': v1_agg_status,
        'guestOSInfo': v1_ga_guest_info
    }

    supported_features = []
    for _, feature in get_agent_supported_features_list_for_crp().items():
        supported_features.append(
            {
                "Key": feature.name,
                "Value": feature.version
            }
        )
    if supported_features:
        v1_vm_status["supportedFeatures"] = supported_features

    return v1_vm_status


class StatusBlob(object):
    def __init__(self, client):
        self.vm_status = None
        self.client = client
        self.type = None
        self.data = None

    def set_vm_status(self, vm_status):
        validate_param("vmAgent", vm_status, VMStatus)
        self.vm_status = vm_status

    def to_json(self):
        report = vm_status_to_v1(self.vm_status)
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
            "x-ms-date": _get_utc_timestamp_for_status_reporting(),
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
            "x-ms-date": _get_utc_timestamp_for_status_reporting(),
            "x-ms-version": self.__class__.__storage_version__
        }

    def get_page_blob_page_headers(self, start, end):
        return {
            "Content-Length": ustr(end - start),
            "x-ms-date": _get_utc_timestamp_for_status_reporting(),
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


class WireClient(object):

    def __init__(self, endpoint):
        logger.info("Wire server endpoint:{0}", endpoint)
        self._endpoint = endpoint
        self._goal_state = None
        self._extensions_goal_state = None  # The goal state to use for extensions; can be an ExtensionsGoalStateFromVmSettings or ExtensionsGoalStateFromExtensionsConfig
        self._cached_vm_settings = None  # Cached value of the most recent ExtensionsGoalStateFromVmSettings
        self._host_plugin = None
        self._host_plugin_version = FlexibleVersion("0.0.0.0")  # Version 0 means "unknown"
        self._host_plugin_supports_vm_settings = False
        self._host_plugin_supports_vm_settings_next_check = datetime.now()
        self.status_blob = StatusBlob(self)
        self.goal_state_flusher = StateFlusher(conf.get_lib_dir())
        self._vm_settings_error_reporter = _VmSettingsErrorReporter()

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

        except Exception as e:
            raise ProtocolError("[Wireserver Exception] {0}".format(
                ustr(e)))

        return resp

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
        except IOError as e:
            raise ProtocolError("Failed to read cache: {0}".format(e))

    @staticmethod
    def _save_cache(data, file_name):
        try:
            file_path = os.path.join(conf.get_lib_dir(), file_name)
            fileutil.write_file(file_path, data)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[file_name])
            raise ProtocolError("Failed to write cache: {0}".format(e))

    @staticmethod
    def call_storage_service(http_req, *args, **kwargs):
        # Default to use the configured HTTP proxy
        if not 'use_proxy' in kwargs or kwargs['use_proxy'] is None:
            kwargs['use_proxy'] = True

        return http_req(*args, **kwargs)

    def fetch_manifest_through_host(self, uri):
        host = self.get_host_plugin()
        uri, headers = host.get_artifact_request(uri)
        response, _ = self.fetch(uri, headers, use_proxy=False, max_retry=1)
        return response

    def fetch_manifest(self, version_uris, timeout_in_minutes=5, timeout_in_ms=0):
        logger.verbose("Fetch manifest")
        version_uris_shuffled = version_uris
        random.shuffle(version_uris_shuffled)

        uris_tried = 0
        start_time = datetime.now()
        for version_uri in version_uris_shuffled:

            if datetime.now() - start_time > timedelta(minutes=timeout_in_minutes, milliseconds=timeout_in_ms):
                logger.warn("Agent timed-out after {0} minutes while fetching extension manifests. {1}/{2} uris tried.",
                    timeout_in_minutes, uris_tried, len(version_uris))
                break

            # GA expects a location and failoverLocation in ExtensionsConfig, but
            # this is not always the case. See #1147.
            if version_uri is None:
                logger.verbose('The specified manifest URL is empty, ignored.')
                continue

            direct_func = lambda: self.fetch(version_uri, max_retry=1)[0]  # pylint: disable=W0640
            # NOTE: the host_func may be called after refreshing the goal state, be careful about any goal state data
            # in the lambda.
            host_func = lambda: self.fetch_manifest_through_host(version_uri)  # pylint: disable=W0640

            try:
                manifest = self.send_request_using_appropriate_channel(direct_func, host_func)
                if manifest is not None:
                    host = self.get_host_plugin()
                    host.update_manifest_uri(version_uri)
                    return manifest
            except Exception as error:
                logger.warn("Failed to fetch manifest from {0}. Error: {1}", version_uri, ustr(error))

            uris_tried += 1

        raise ExtensionDownloadError("Failed to fetch manifest from all sources")

    def stream(self, uri, destination, headers=None, use_proxy=None, max_retry=None):
        """
        max_retry indicates the maximum number of retries for the HTTP request; None indicates that the default value should be used
        """
        success = False
        logger.verbose("Fetch [{0}] with headers [{1}] to file [{2}]", uri, headers, destination)

        response = self._fetch_response(uri, headers, use_proxy,  max_retry=max_retry)
        if response is not None and not restutil.request_failed(response):
            chunk_size = 1024 * 1024  # 1MB buffer
            try:
                with open(destination, 'wb', chunk_size) as destination_fh:
                    complete = False
                    while not complete:
                        chunk = response.read(chunk_size)
                        destination_fh.write(chunk)
                        complete = len(chunk) < chunk_size
                success = True
            except Exception as error:
                logger.error('Error streaming {0} to {1}: {2}'.format(uri, destination, ustr(error)))

        return success

    def fetch(self, uri, headers=None, use_proxy=None, decode=True, max_retry=None, ok_codes=None):
        """
        max_retry indicates the maximum number of retries for the HTTP request; None indicates that the default value should be used

        Returns a tuple with the content and headers of the response. The headers are a list of (name, value) tuples.
        """
        logger.verbose("Fetch [{0}] with headers [{1}]", uri, headers)
        content = None
        response_headers = None
        response = self._fetch_response(uri, headers, use_proxy, max_retry=max_retry, ok_codes=ok_codes)
        if response is not None and not restutil.request_failed(response, ok_codes=ok_codes):
            response_content = response.read()
            content = self.decode_config(response_content) if decode else response_content
            response_headers = response.getheaders()
        return content, response_headers

    def _fetch_response(self, uri, headers=None, use_proxy=None, max_retry=None, ok_codes=None):
        """
        max_retry indicates the maximum number of retries for the HTTP request; None indicates that the default value should be used
        """
        resp = None
        try:
            resp = self.call_storage_service(
                restutil.http_get,
                uri,
                headers=headers,
                use_proxy=use_proxy,
                max_retry=max_retry)

            host_plugin = self.get_host_plugin()

            if restutil.request_failed(resp, ok_codes=ok_codes):
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

        except (HttpError, ProtocolError, IOError) as error:
            msg = "Fetch failed: {0}".format(error)
            logger.warn(msg)
            report_event(op=WALAEventOperation.HttpGet, is_success=False, message=msg, log_event=False)

            if isinstance(error, (InvalidContainerError, ResourceGoneError)):
                # These are retryable errors that should force a goal state refresh in the host plugin
                raise

        return resp

    def update_host_plugin_from_goal_state(self):
        """
        Fetches a new goal state and updates the Container ID and Role Config Name of the host plugin client
        """
        goal_state = GoalState(self)
        self._update_host_plugin(goal_state.container_id, goal_state.role_config_name)

    def update_goal_state(self, force_update=False):
        """
        Updates the goal state if the incarnation or etag changed or if 'force_update' is True
        """
        try:
            #
            # The goal state needs to be retrieved using both the WireServer (via the GoalState class) and the HostGAPlugin
            # (via the self._fetch_vm_settings_goal_state method).
            #
            # We always need at least 2 queries: one to the WireServer (to check for incarnation changes) and one to the HostGAPlugin
            # (to check for extension updates).
            #
            # We start by fetching the goal state from the WireServer. The response to this initial query will include the incarnation,
            # container ID, role config, and URLs to the rest of the goal state (certificates, remote users, extensions config, etc). We
            # do this first because we need to initialize the HostGAPlugin with the container ID and role config.
            #
            goal_state = GoalState(self)

            self._update_host_plugin(goal_state.container_id, goal_state.role_config_name)

            #
            # Then we fetch the vmSettings from the HostGAPlugin; the response will include the goal state for extensions.
            #
            vm_settings_goal_state, vm_settings_goal_state_updated = (None, False)

            if conf.get_enable_fast_track():
                try:
                    vm_settings_goal_state, vm_settings_goal_state_updated = self._fetch_vm_settings_goal_state(force_update=force_update)
                except VmSettingsNotSupported:
                    pass  # if vmSettings are not supported we use extensionsConfig below

            #
            # Now we fetch the rest of the goal state from the WireServer (but ony if needed: initialization, a "forced" update, or
            # a change in the incarnation). Note that if we fetch the full goal state we also update self._goal_state.
            #
            if force_update:
                logger.info("Forcing an update of the goal state..")

            fetch_full_goal_state = force_update or self._goal_state is None or self._goal_state.incarnation != goal_state.incarnation

            if not fetch_full_goal_state:
                goal_state_updated = False
            else:
                goal_state.fetch_full_goal_state(self)
                self._goal_state = goal_state
                goal_state_updated = True

            #
            # And, lastly, we fall back to extensionsConfig if Fast Track is disabled or not supported
            #
            if vm_settings_goal_state is not None:
                self._extensions_goal_state = vm_settings_goal_state
            else:
                self._extensions_goal_state = self._goal_state.extensions_config

            #
            # If either goal state changed (goal_state or vm_settings_goal_state) save them
            #
            if goal_state_updated or vm_settings_goal_state_updated:
                self._save_goal_state()

        except ProtocolError:
            raise
        except Exception as exception:
            raise ProtocolError("Error fetching goal state: {0}".format(ustr(exception)))

    def _fetch_vm_settings_goal_state(self, force_update):
        """
        Queries the vmSettings from the HostGAPlugin and returns an (ExtensionsGoalStateFromVmSettings, bool) tuple with the vmSettings and
        a boolean indicating if they are an updated (True) or a cached value (False).

        Raises TypeError if the HostGAPlugin does not support the vmSettings API, or ProtocolError if the request fails for any other reason
        (e.g. not supported, time out, server error).
        """
        def raise_not_supported(reset_state=False):
            if reset_state:
                self._host_plugin_supports_vm_settings = False
                self._host_plugin_supports_vm_settings_next_check = datetime.now() + timedelta(hours=6)  # check again in 6 hours
                # "Not supported" is not considered an error, so don't use self._vm_settings_error_reporter to report it
                logger.info("vmSettings is not supported")
                add_event(op=WALAEventOperation.HostPlugin, message="vmSettings is not supported", is_success=True)
            raise VmSettingsNotSupported()

        try:
            # Raise if VmSettings are not supported but check for periodically since the HostGAPlugin could have been updated since the last check
            if not self._host_plugin_supports_vm_settings and self._host_plugin_supports_vm_settings_next_check > datetime.now():
                raise_not_supported()

            etag = None if force_update or self._cached_vm_settings is None else self._cached_vm_settings.etag
            correlation_id = str(uuid.uuid4())

            def format_message(msg):
                return "GET vmSettings [correlation ID: {0} eTag: {1}]: {2}".format(correlation_id, etag, msg)

            def get_vm_settings():
                url, headers = self.get_host_plugin().get_vm_settings_request(correlation_id)
                if etag is not None:
                    headers['if-none-match'] = etag
                return restutil.http_get(url, headers=headers, use_proxy=False, max_retry=1, return_raw_response=True)

            self._vm_settings_error_reporter.report_request()

            response = get_vm_settings()

            if response.status == httpclient.GONE:  # retry after refreshing the HostGAPlugin
                self.update_host_plugin_from_goal_state()
                response = get_vm_settings()

            if response.status == httpclient.NOT_FOUND:  # the HostGAPlugin does not support FastTrack
                raise_not_supported(reset_state=True)

            if response.status == httpclient.NOT_MODIFIED:  # The goal state hasn't changed, return the current instance
                return self._cached_vm_settings, False

            if response.status != httpclient.OK:
                error_description = restutil.read_response_error(response)
                # For historical reasons the HostGAPlugin returns 502 (BAD_GATEWAY) for internal errors instead of using
                # 500 (INTERNAL_SERVER_ERROR). We add a short prefix to the error message in the hope that it will help
                # clear any confusion produced by the poor choice of status code.
                if response.status == httpclient.BAD_GATEWAY:
                    error_description = "[Internal error in HostGAPlugin] {0}".format(error_description)
                error_description = format_message(error_description)

                if 400 <= response.status <= 499:
                    self._vm_settings_error_reporter.report_error(error_description, _VmSettingsError.ClientError)
                elif 500 <= response.status <= 599:
                    self._vm_settings_error_reporter.report_error(error_description, _VmSettingsError.ServerError)
                else:
                    self._vm_settings_error_reporter.report_error(error_description)

                raise ProtocolError(error_description)

            for h in response.getheaders():
                if h[0].lower() == 'etag':
                    response_etag = h[1]
                    break
            else:  # since the vmSettings were updated, the response must include an etag
                message = format_message("The vmSettings response does not include an Etag header")
                self._vm_settings_error_reporter.report_error(message)
                raise ProtocolError(message)

            response_content = self.decode_config(response.read())
            vm_settings = ExtensionsGoalStateFactory.create_from_vm_settings(response_etag, response_content)

            # log the HostGAPlugin version
            if vm_settings.host_ga_plugin_version != self._host_plugin_version:
                self._host_plugin_version = vm_settings.host_ga_plugin_version
                message = "HostGAPlugin version: {0}".format(vm_settings.host_ga_plugin_version)
                logger.info(message)
                add_event(op=WALAEventOperation.HostPlugin, message=message, is_success=True)

            # Don't support HostGAPlugin versions older than 115
            if vm_settings.host_ga_plugin_version < FlexibleVersion("1.0.8.115"):
                raise_not_supported(reset_state=True)

            logger.info("Fetched new vmSettings [correlation ID: {0} New eTag: {1}]", correlation_id, vm_settings.etag)
            self._host_plugin_supports_vm_settings = True
            self._cached_vm_settings = vm_settings
            return vm_settings, True

        except (ProtocolError, VmSettingsNotSupported):
            raise
        except Exception as exception:
            if isinstance(exception, IOError) and "timed out" in ustr(exception):
                message = format_message("Timeout")
                self._vm_settings_error_reporter.report_error(message, _VmSettingsError.Timeout)
            else:
                message = format_message("Request failed: {0}".format(textutil.format_exception(exception)))
                self._vm_settings_error_reporter.report_error(message, _VmSettingsError.RequestFailed)
            raise ProtocolError(message)
        finally:
            self._vm_settings_error_reporter.report_summary()

    def _update_host_plugin(self, container_id, role_config_name):
        if self._host_plugin is not None:
            self._host_plugin.update_container_id(container_id)
            self._host_plugin.update_role_config_name(role_config_name)

    def _save_goal_state(self):
        try:
            self.goal_state_flusher.flush()
        except Exception as e:
            logger.warn("Failed to save the previous goal state to the history folder: {0}", ustr(e))

        try:
            def save_if_not_none(goal_state_property, file_name):
                if goal_state_property is not None and goal_state_property.xml_text is not None:
                    self._save_cache(goal_state_property.xml_text, file_name)

            # NOTE: Certificates are saved in Certificate.__init__
            self._save_cache(self._goal_state.incarnation, INCARNATION_FILE_NAME)
            save_if_not_none(self._goal_state, GOAL_STATE_FILE_NAME.format(self._goal_state.incarnation))
            save_if_not_none(self._goal_state.hosting_env, HOSTING_ENV_FILE_NAME)
            save_if_not_none(self._goal_state.shared_conf, SHARED_CONF_FILE_NAME)
            save_if_not_none(self._goal_state.remote_access, REMOTE_ACCESS_FILE_NAME.format(self._goal_state.incarnation))
            if self._goal_state.extensions_config is not None:
                text = self._goal_state.extensions_config.get_redacted_text()
                if text != '':
                    self._save_cache(text, EXT_CONF_FILE_NAME.format(self._goal_state.extensions_config.incarnation))
            # TODO: When Fast Track is fully enabled self._cached_vm_settings will go away and this can be deleted
            if self._cached_vm_settings is not None:
                text = self._cached_vm_settings.get_redacted_text()
                if text != '':
                    self._save_cache(text, VM_SETTINGS_FILE_NAME.format(self._cached_vm_settings.id))
            # END TODO

        except Exception as e:
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

    def get_extensions_goal_state(self):
        if self._extensions_goal_state is None:
            raise ProtocolError("Trying to fetch ExtensionsGoalState before initialization!")

        return self._extensions_goal_state

    def get_ext_manifest(self, ext_handler):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Extension Manifest before initialization!")

        try:
            xml_text = self.fetch_manifest(ext_handler.manifest_uris)
            self._save_cache(xml_text, MANIFEST_FILE_NAME.format(ext_handler.name, self.get_goal_state().incarnation))
            return ExtensionManifest(xml_text)
        except Exception as e:
            raise ExtensionDownloadError("Failed to retrieve extension manifest. Error: {0}".format(ustr(e)))

    def get_remote_access(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Remote Access before initialization!")
        return self._goal_state.remote_access

    def fetch_gafamily_manifest(self, vmagent_manifest, goal_state):
        local_file = MANIFEST_FILE_NAME.format(vmagent_manifest.family, goal_state.incarnation)
        local_file = os.path.join(conf.get_lib_dir(), local_file)

        try:
            xml_text = self.fetch_manifest(vmagent_manifest.uris)
            fileutil.write_file(local_file, xml_text)
            return ExtensionManifest(xml_text)
        except Exception as e:
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

    def _call_hostplugin_with_container_check(self, host_func):
        """
        Calls host_func on host channel and accounts for stale resource (ResourceGoneError or InvalidContainerError).
        If stale, it refreshes the goal state and retries host_func.
        This method can throw, so the callers need to handle that.
        """
        try:
            ret = host_func()
            if ret in (None, False):
                raise Exception("Request failed using the host channel.")

            return ret
        except (ResourceGoneError, InvalidContainerError) as error:
            host_plugin = self.get_host_plugin()

            old_container_id, old_role_config_name = host_plugin.container_id, host_plugin.role_config_name
            msg = "[PERIODIC] Request failed with the current host plugin configuration. " \
                  "ContainerId: {0}, role config file: {1}. Fetching new goal state and retrying the call." \
                  "Error: {2}".format(old_container_id, old_role_config_name, ustr(error))
            logger.periodic_info(logger.EVERY_SIX_HOURS, msg)

            self.update_host_plugin_from_goal_state()

            new_container_id, new_role_config_name = host_plugin.container_id, host_plugin.role_config_name
            msg = "[PERIODIC] Host plugin reconfigured with new parameters. " \
                  "ContainerId: {0}, role config file: {1}.".format(new_container_id, new_role_config_name)
            logger.periodic_info(logger.EVERY_SIX_HOURS, msg)

            try:
                ret = host_func()

                if ret in (None, False):
                    raise Exception("Request failed using the host channel after goal state refresh.")

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
                return ret
            except (ResourceGoneError, InvalidContainerError) as error:
                msg = "[PERIODIC] Request failed using the host plugin channel after goal state refresh. " \
                      "ContainerId changed from {0} to {1}, role config file changed from {2} to {3}. " \
                      "Exception type: {4}.".format(old_container_id, new_container_id, old_role_config_name,
                                                    new_role_config_name, type(error).__name__)
                add_periodic(delta=logger.EVERY_SIX_HOURS,
                             name=AGENT_NAME,
                             version=CURRENT_VERSION,
                             op=WALAEventOperation.HostPlugin,
                             is_success=False,
                             message=msg,
                             log_event=True)
                raise

    def __send_request_using_host_channel(self, host_func):
        """
        Calls the host_func on host channel with retries for stale goal state and handles any exceptions, consistent with the caller for direct channel.
        At the time of writing, host_func internally calls either:
        1) WireClient.stream which returns a boolean, or
        2) WireClient.fetch which returns None or a HTTP response.
        This method returns either None (failure case where host_func returned None or False), True or an HTTP response.
        """
        ret = None
        try:
            ret = self._call_hostplugin_with_container_check(host_func)
        except Exception as error:
            logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the host channel. Error: {0}".format(ustr(error)))

        return ret

    @staticmethod
    def __send_request_using_direct_channel(direct_func):
        """
        Calls the direct_func on direct channel and handles any exceptions, consistent with the caller for host channel.
        At the time of writing, direct_func internally calls either:
        1) WireClient.stream which returns a boolean, or
        2) WireClient.fetch which returns None or a HTTP response.
        This method returns either None (failure case where direct_func returned None or False), True or an HTTP response.
        """
        ret = None
        try:
            ret = direct_func()

            if ret in (None, False):
                logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel.")
                return None
        except Exception as error:
            logger.periodic_info(logger.EVERY_HOUR, "[PERIODIC] Request failed using the direct channel. Error: {0}".format(ustr(error)))

        return ret

    def send_request_using_appropriate_channel(self, direct_func, host_func):
        """
        Determines which communication channel to use. By default, the primary channel is direct, host channel is secondary.
        We call the primary channel first and return on success. If primary fails, we try secondary. If secondary fails,
        we return and *don't* switch the default channel. If secondary succeeds, we change the default channel.
        This method doesn't raise since the calls to direct_func and host_func are already wrapped and handle any exceptions.
        Possible return values are manifest, artifacts profile, True or None.
        """
        direct_channel = lambda: self.__send_request_using_direct_channel(direct_func)
        host_channel = lambda: self.__send_request_using_host_channel(host_func)

        if HostPluginProtocol.is_default_channel:
            primary_channel, secondary_channel = host_channel, direct_channel
        else:
            primary_channel, secondary_channel = direct_channel, host_channel

        ret = primary_channel()
        if ret is not None:
            return ret

        ret = secondary_channel()
        if ret is not None:
            HostPluginProtocol.is_default_channel = not HostPluginProtocol.is_default_channel
            message = "Default channel changed to {0} channel.".format("HostGA" if HostPluginProtocol.is_default_channel else "direct")
            logger.info(message)
            add_event(AGENT_NAME, op=WALAEventOperation.DefaultChannelChange, version=CURRENT_VERSION, is_success=True, message=message, log_event=False)
        return ret

    def upload_status_blob(self):
        extensions_goal_state = self.get_extensions_goal_state()

        if extensions_goal_state.status_upload_blob is None:
            # the status upload blob is in ExtensionsConfig so force a full goal state refresh
            self.update_goal_state(force_update=True)
            extensions_goal_state = self.get_extensions_goal_state()

        if extensions_goal_state.status_upload_blob is None:
            raise ProtocolNotFoundError("Status upload uri is missing")

        blob_type = extensions_goal_state.status_upload_blob_type

        try:
            self.status_blob.prepare(blob_type)
        except Exception as e:
            raise ProtocolError("Exception creating status blob: {0}".format(ustr(e)))

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
            host.put_vm_status(self.status_blob, extensions_goal_state.status_upload_blob, extensions_goal_state.status_upload_blob_type)
            return
        except ResourceGoneError:
            # refresh the host plugin client and try again on the next iteration of the main loop
            self.update_host_plugin_from_goal_state()
            return
        except Exception as e:
            # for all other errors, fall back to direct
            msg = "Falling back to direct upload: {0}".format(ustr(e))
            self.report_status_event(msg, is_success=True)

        try:
            if self.status_blob.upload(extensions_goal_state.status_upload_blob):
                return
        except Exception as e:
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
        except HttpError as e:
            raise ProtocolError((u"Failed to send provision status: "
                                 u"{0}").format(e))
        if restutil.request_failed(resp):
            raise ProtocolError((u"Failed to send provision status: "
                                 u",{0}: {1}").format(resp.status,
                                                      resp.read()))

    def send_encoded_event(self, provider_id, event_str, encoding='utf8'):
        uri = TELEMETRY_URI.format(self.get_endpoint())
        data_format_header = ustr('<?xml version="1.0"?><TelemetryData version="1.0"><Provider id="{0}">').format(
            provider_id).encode(encoding)
        data_format_footer = ustr('</Provider></TelemetryData>').encode(encoding)
        # Event string should already be encoded by the time it gets here, to avoid double encoding,
        # dividing it into parts.
        data = data_format_header + event_str + data_format_footer
        try:
            header = self.get_header_for_xml_content()
            # NOTE: The call to wireserver requests utf-8 encoding in the headers, but the body should not
            #       be encoded: some nodes in the telemetry pipeline do not support utf-8 encoding.
            resp = self.call_wireserver(restutil.http_post, uri, data, header)
        except HttpError as e:
            raise ProtocolError("Failed to send events:{0}".format(e))

        if restutil.request_failed(resp):
            logger.verbose(resp.read())
            raise ProtocolError(
                "Failed to send events:{0}".format(resp.status))

    def report_event(self, events_iterator):
        buf = {}
        debug_info = CollectOrReportEventDebugInfo(operation=CollectOrReportEventDebugInfo.OP_REPORT)
        events_per_provider = defaultdict(int)

        def _send_event(provider_id, debug_info):
            try:
                self.send_encoded_event(provider_id, buf[provider_id])
            except UnicodeError as uni_error:
                debug_info.update_unicode_error(uni_error)
            except Exception as error:
                debug_info.update_op_error(error)

        # Group events by providerId
        for event in events_iterator:
            try:
                if event.providerId not in buf:
                    buf[event.providerId] = b""
                event_str = event_to_v1_encoded(event)

                if len(event_str) >= MAX_EVENT_BUFFER_SIZE:
                    # Ignore single events that are too large to send out
                    details_of_event = [ustr(x.name) + ":" + ustr(x.value) for x in event.parameters if x.name in
                                        [GuestAgentExtensionEventsSchema.Name, GuestAgentExtensionEventsSchema.Version,
                                         GuestAgentExtensionEventsSchema.Operation,
                                         GuestAgentExtensionEventsSchema.OperationSuccess]]
                    logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                         "Single event too large: {0}, with the length: {1} more than the limit({2})"
                                         .format(str(details_of_event), len(event_str), MAX_EVENT_BUFFER_SIZE))
                    continue

                # If buffer is full, send out the events in buffer and reset buffer
                if len(buf[event.providerId] + event_str) >= MAX_EVENT_BUFFER_SIZE:
                    logger.verbose("No of events this request = {0}".format(events_per_provider[event.providerId]))
                    _send_event(event.providerId, debug_info)
                    buf[event.providerId] = b""
                    events_per_provider[event.providerId] = 0

                # Add encoded events to the buffer
                buf[event.providerId] = buf[event.providerId] + event_str
                events_per_provider[event.providerId] += 1

            except Exception as error:
                logger.warn("Unexpected error when generating Events:{0}", textutil.format_exception(error))

        # Send out all events left in buffer.
        for provider_id in list(buf.keys()):
            if buf[provider_id]:
                logger.verbose("No of events this request = {0}".format(events_per_provider[provider_id]))
                _send_event(provider_id, debug_info)

        debug_info.report_debug_info()

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
            goal_state = GoalState(self)
            self._set_host_plugin(HostPluginProtocol(self.get_endpoint(), goal_state.container_id, goal_state.role_config_name))
        return self._host_plugin

    def get_on_hold(self):
        return self.get_extensions_goal_state().on_hold

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
        if not textutil.is_str_empty(artifacts_profile):
            self.__dict__.update(parse_json(artifacts_profile))

    def is_on_hold(self):
        # hasattr() is not available in Python 2.6
        if 'onHold' in self.__dict__:
            return str(self.onHold).lower() == 'true'  # pylint: disable=E1101
        return False


class _VmSettingsError(object):
    ServerError   = 'ServerError'
    ClientError   = 'ClientError'
    Timeout       = 'Timeout'
    RequestFailed = 'RequestFailed'


class _VmSettingsErrorReporter(object):
    _MaxErrors = 5  # Max number of error reported by period
    _Period = timedelta(hours=1)  # How often to report the summary

    def __init__(self):
        self._reset()

    def _reset(self):
        self._request_count = 0  # Total number of vmSettings HTTP requests
        self._error_count = 0   # Total number of errors issuing vmSettings requests (includes all kinds of errors)
        self._server_error_count = 0  # Count of server side errors (HTTP status in the 500s)
        self._client_error_count = 0  # Count of client side errors (HTTP status in the 400s)
        self._timeout_count = 0  # Count of timeouts on vmSettings requests
        self._request_failure_count = 0  # Total count of requests that could not be issued (does not include timeouts or requests that were actually issued and failed, for example, with 500 or 400 statuses)
        self._next_period = datetime.now() + _VmSettingsErrorReporter._Period

    def report_request(self):
        self._request_count += 1

    def report_error(self, error, category=None):
        self._error_count += 1

        if self._error_count <= _VmSettingsErrorReporter._MaxErrors:
            add_event(op=WALAEventOperation.VmSettings, message=error, is_success=False, log_event=False)

        if category == _VmSettingsError.ServerError:
            self._server_error_count += 1
        elif category == _VmSettingsError.ClientError:
            self._client_error_count += 1
        elif category == _VmSettingsError.Timeout:
            self._timeout_count += 1
        elif category == _VmSettingsError.RequestFailed:
            self._request_failure_count += 1

    def report_summary(self):
        if datetime.now() >= self._next_period:
            summary = {
                "requests":       self._request_count,
                "errors":         self._error_count,
                "serverErrors":   self._server_error_count,
                "clientErrors":   self._client_error_count,
                "timeouts":       self._timeout_count,
                "failedRequests": self._request_failure_count
            }
            # always send telemetry, but log errors only
            message = json.dumps(summary)
            add_event(op=WALAEventOperation.VmSettingsSummary, message=message, is_success=False, log_event=False)
            if self._error_count > 0:
                logger.info("[VmSettingsSummary] {0}", message)

            self._reset()


class VmSettingsNotSupported(TypeError):
    pass
