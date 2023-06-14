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
import shutil
import time
import zipfile

from collections import defaultdict
from datetime import datetime, timedelta
from xml.sax import saxutils

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_crp, SupportedFeatureNames
from azurelinuxagent.common.datacontract import validate_param
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_event, \
    CollectOrReportEventDebugInfo, add_periodic
from azurelinuxagent.common.exception import ProtocolNotFoundError, \
    ResourceGoneError, ExtensionDownloadError, InvalidContainerError, ProtocolError, HttpError, ExtensionErrorCodes
from azurelinuxagent.common.future import httpclient, bytebuffer, ustr
from azurelinuxagent.common.protocol.goal_state import GoalState, TRANSPORT_CERT_FILE_NAME, TRANSPORT_PRV_FILE_NAME, \
    GoalStateProperties
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import DataContract, ProvisionStatus, VMInfo, VMStatus
from azurelinuxagent.common.telemetryevent import GuestAgentExtensionEventsSchema
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, \
    findtext, gettext, remove_bom, get_bytes_from_pem, parse_json
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

VERSION_INFO_URI = "http://{0}/?comp=versions"
HEALTH_REPORT_URI = "http://{0}/machine?comp=health"
ROLE_PROP_URI = "http://{0}/machine?comp=roleProperties"
TELEMETRY_URI = "http://{0}/machine?comp=telemetrydata"

PROTOCOL_VERSION = "2012-11-30"
ENDPOINT_FINE_NAME = "WireServer"

SHORT_WAITING_INTERVAL = 1  # 1 second

MAX_EVENT_BUFFER_SIZE = 2 ** 16 - 2 ** 10

_DOWNLOAD_TIMEOUT = timedelta(minutes=5)


class UploadError(HttpError):
    pass


class WireProtocol(DataContract):
    def __init__(self, endpoint):
        if endpoint is None:
            raise ProtocolError("WireProtocol endpoint is None")
        self.client = WireClient(endpoint)

    def detect(self, init_goal_state=True):
        self.client.check_wire_protocol_version()

        trans_prv_file = os.path.join(conf.get_lib_dir(),
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        cryptutil = CryptUtil(conf.get_openssl_cmd())
        cryptutil.gen_transport_cert(trans_prv_file, trans_cert_file)

        # Initialize the goal state, including all the inner properties
        if init_goal_state:
            logger.info('Initializing goal state during protocol detection')
            self.client.reset_goal_state()

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

    def get_goal_state(self):
        return self.client.get_goal_state()

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
    if vm_status.vmAgent.supports_fast_track:
        supported_features.append(
            {
                "Key": SupportedFeatureNames.FastTrack,
                "Value": "1.0"  # This is a dummy version; CRP ignores it
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
        self._host_plugin = None
        self.status_blob = StatusBlob(self)

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
            raise ProtocolError("[Wireserver Exception] {0}".format(ustr(e)))

        return resp

    def decode_config(self, data):
        if data is None:
            return None
        data = remove_bom(data)
        xml_text = ustr(data, encoding='utf-8')
        return xml_text

    def fetch_config(self, uri, headers):
        resp = self.call_wireserver(restutil.http_get, uri, headers=headers)
        return self.decode_config(resp.read())

    @staticmethod
    def call_storage_service(http_req, *args, **kwargs):
        # Default to use the configured HTTP proxy
        if not 'use_proxy' in kwargs or kwargs['use_proxy'] is None:
            kwargs['use_proxy'] = True

        return http_req(*args, **kwargs)

    def fetch_artifacts_profile_blob(self, uri):
        return self._fetch_content("artifacts profile blob", [uri], use_verify_header=False)[1]  # _fetch_content returns a (uri, content) tuple

    def fetch_manifest(self, manifest_type, uris, use_verify_header):
        uri, content = self._fetch_content("{0} manifest".format(manifest_type), uris, use_verify_header=use_verify_header)
        self.get_host_plugin().update_manifest_uri(uri)
        return content

    def _fetch_content(self, download_type, uris, use_verify_header):
        """
        Walks the given list of 'uris' issuing HTTP GET requests; returns a tuple with the URI and the content of the first successful request.

        The 'download_type' is added to any log messages produced by this method; it should describe the type of content of the given URIs
        (e.g. "manifest", "extension package", etc).
        """
        host_ga_plugin = self.get_host_plugin()

        direct_download = lambda uri: self.fetch(uri)[0]

        def hgap_download(uri):
            request_uri, request_headers = host_ga_plugin.get_artifact_request(uri, use_verify_header=use_verify_header)
            response, _ = self.fetch(request_uri, request_headers, use_proxy=False, retry_codes=restutil.HGAP_GET_EXTENSION_ARTIFACT_RETRY_CODES)
            return response

        return self._download_with_fallback_channel(download_type, uris, direct_download=direct_download, hgap_download=hgap_download)

    def download_zip_package(self, package_type, uris, target_file, target_directory, use_verify_header):
        """
        Downloads the ZIP package specified in 'uris' (which is a list of alternate locations for the ZIP), saving it to 'target_file' and then expanding
        its contents to 'target_directory'. Deletes the target file after it has been expanded.

        The 'package_type' is only used in log messages and has no other semantics. It should specify the contents of the ZIP, e.g. "extension package"
        or "agent package"

        The 'use_verify_header' parameter indicates whether the verify header should be added when using the extensionArtifact API of the HostGAPlugin.
        """
        host_ga_plugin = self.get_host_plugin()

        direct_download = lambda uri: self.stream(uri, target_file, headers=None, use_proxy=True)

        def hgap_download(uri):
            request_uri, request_headers = host_ga_plugin.get_artifact_request(uri, use_verify_header=use_verify_header, artifact_manifest_url=host_ga_plugin.manifest_uri)
            return self.stream(request_uri, target_file, headers=request_headers, use_proxy=False)

        on_downloaded = lambda: WireClient._try_expand_zip_package(package_type, target_file, target_directory)

        self._download_with_fallback_channel(package_type, uris, direct_download=direct_download, hgap_download=hgap_download, on_downloaded=on_downloaded)

    def _download_with_fallback_channel(self, download_type, uris, direct_download, hgap_download, on_downloaded=None):
        """
        Walks the given list of 'uris' issuing HTTP GET requests, attempting to download the content of each URI. The download is done using both the default and
        the fallback channels, until one of them succeeds. The 'direct_download' and 'hgap_download' functions define the logic to do direct calls to the URI or
        to use the HostGAPlugin as a proxy for the download. Initially the default channel is the direct download and the fallback channel is the HostGAPlugin,
        but the default can be depending on the success/failure of each channel (see _download_using_appropriate_channel() for the logic to do this).

        The 'download_type' is added to any log messages produced by this method; it should describe the type of content of the given URIs
        (e.g. "manifest", "extension package, "agent package", etc).

        When the download is successful, _download_with_fallback_channel invokes the 'on_downloaded' function, which can be used to process the results of the download. This
        function should return True on success, and False on failure (it should not raise any exceptions). If the return value is False, the download is considered
        a failure and the next URI is tried.

        When the download succeeds, this method returns a (uri, response) tuple where the first item is the URI of the successful download and the second item is
        the response returned by the successful channel (i.e. one of direct_download and hgap_download).

        This method enforces a timeout (_DOWNLOAD_TIMEOUT) on the download and raises an exception if the limit is exceeded.
        """
        logger.info("Downloading {0}", download_type)
        start_time = datetime.now()

        uris_shuffled = uris
        random.shuffle(uris_shuffled)
        most_recent_error = "None"

        for index, uri in enumerate(uris_shuffled):
            elapsed = datetime.now() - start_time
            if elapsed > _DOWNLOAD_TIMEOUT:
                message = "Timeout downloading {0}. Elapsed: {1} URIs tried: {2}/{3}. Last error: {4}".format(download_type, elapsed, index, len(uris), ustr(most_recent_error))
                raise ExtensionDownloadError(message, code=ExtensionErrorCodes.PluginManifestDownloadError)

            try:
                # Disable W0640: OK to use uri in a lambda within the loop's body
                response = self._download_using_appropriate_channel(lambda: direct_download(uri), lambda: hgap_download(uri))  # pylint: disable=W0640

                if on_downloaded is not None:
                    on_downloaded()

                return uri, response
            except Exception as exception:
                most_recent_error = exception

        raise ExtensionDownloadError("Failed to download {0} from all URIs. Last error: {1}".format(download_type, ustr(most_recent_error)), code=ExtensionErrorCodes.PluginManifestDownloadError)

    @staticmethod
    def _try_expand_zip_package(package_type, target_file, target_directory):
        logger.info("Unzipping {0}: {1}", package_type, target_file)
        try:
            zipfile.ZipFile(target_file).extractall(target_directory)
        except Exception as exception:
            logger.error("Error while unzipping {0}: {1}", package_type, ustr(exception))
            if os.path.exists(target_directory):
                try:
                    shutil.rmtree(target_directory)
                except Exception as exception:
                    logger.warn("Cannot delete {0}: {1}", target_directory, ustr(exception))
            raise
        finally:
            try:
                os.remove(target_file)
            except Exception as exception:
                logger.warn("Cannot delete {0}: {1}", target_file, ustr(exception))

    def stream(self, uri, destination, headers=None, use_proxy=None):
        """
        Downloads the content of the given 'uri' and saves it to the 'destination' file.
        """
        try:
            logger.verbose("Fetch [{0}] with headers [{1}] to file [{2}]", uri, headers, destination)

            response = self._fetch_response(uri, headers, use_proxy)
            if response is not None and not restutil.request_failed(response):
                chunk_size = 1024 * 1024  # 1MB buffer
                with open(destination, 'wb', chunk_size) as destination_fh:
                    complete = False
                    while not complete:
                        chunk = response.read(chunk_size)
                        destination_fh.write(chunk)
                        complete = len(chunk) < chunk_size
            return ""
        except:
            if os.path.exists(destination):  # delete the destination file, in case we did a partial download
                try:
                    os.remove(destination)
                except Exception as exception:
                    logger.warn("Can't delete {0}: {1}", destination, ustr(exception))
            raise

    def fetch(self, uri, headers=None, use_proxy=None, decode=True, retry_codes=None, ok_codes=None):
        """
        Returns a tuple with the content and headers of the response. The headers are a list of (name, value) tuples.
        """
        logger.verbose("Fetch [{0}] with headers [{1}]", uri, headers)
        content = None
        response_headers = None
        response = self._fetch_response(uri, headers, use_proxy, retry_codes=retry_codes, ok_codes=ok_codes)
        if response is not None and not restutil.request_failed(response, ok_codes=ok_codes):
            response_content = response.read()
            content = self.decode_config(response_content) if decode else response_content
            response_headers = response.getheaders()
        return content, response_headers

    def _fetch_response(self, uri, headers=None, use_proxy=None, retry_codes=None, ok_codes=None):
        resp = None
        try:
            resp = self.call_storage_service(
                restutil.http_get,
                uri,
                headers=headers,
                use_proxy=use_proxy,
                retry_codes=retry_codes)

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
            raise

        return resp

    def update_host_plugin_from_goal_state(self):
        """
        Fetches a new goal state and updates the Container ID and Role Config Name of the host plugin client
        """
        if self._host_plugin is not None:
            GoalState.update_host_plugin_headers(self)

    def update_host_plugin(self, container_id, role_config_name):
        if self._host_plugin is not None:
            self._host_plugin.update_container_id(container_id)
            self._host_plugin.update_role_config_name(role_config_name)

    def update_goal_state(self, silent=False):
        """
        Updates the goal state if the incarnation or etag changed
        """
        try:
            if self._goal_state is None:
                self._goal_state = GoalState(self, silent=silent)
            else:
                self._goal_state.update(silent=silent)

        except ProtocolError:
            raise
        except Exception as exception:
            raise ProtocolError("Error fetching goal state: {0}".format(ustr(exception)))

    def reset_goal_state(self, goal_state_properties=GoalStateProperties.All, silent=False):
        """
        Resets the goal state
        """
        try:
            if not silent:
                logger.info("Forcing an update of the goal state.")

            self._goal_state = GoalState(self, goal_state_properties=goal_state_properties, silent=silent)

        except ProtocolError:
            raise
        except Exception as exception:
            raise ProtocolError("Error fetching goal state: {0}".format(ustr(exception)))

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

    def get_remote_access(self):
        if self._goal_state is None:
            raise ProtocolError("Trying to fetch Remote Access before initialization!")
        return self._goal_state.remote_access

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
        """
        try:
            return host_func()
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

    def _download_using_appropriate_channel(self, direct_download, hgap_download):
        """
        Does a download using both the default and fallback channels. By default, the primary channel is direct, host channel is the fallback.
        We call the primary channel first and return on success. If primary fails, we try the fallback. If fallback fails,
        we return and *don't* switch the default channel. If fallback succeeds, we change the default channel.
        """
        hgap_download_function_with_retry = lambda: self._call_hostplugin_with_container_check(hgap_download)

        if HostPluginProtocol.is_default_channel:
            primary_channel, secondary_channel = hgap_download_function_with_retry, direct_download
        else:
            primary_channel, secondary_channel = direct_download, hgap_download_function_with_retry

        try:
            return primary_channel()
        except Exception as exception:
            primary_channel_error = exception

        try:
            return_value = secondary_channel()

            # Since the secondary channel succeeded, flip the default channel
            HostPluginProtocol.is_default_channel = not HostPluginProtocol.is_default_channel
            message = "Default channel changed to {0} channel.".format("HostGAPlugin" if HostPluginProtocol.is_default_channel else "Direct")
            logger.info(message)
            add_event(AGENT_NAME, op=WALAEventOperation.DefaultChannelChange, version=CURRENT_VERSION, is_success=True, message=message, log_event=False)

            return return_value
        except Exception as exception:
            raise HttpError("Download failed both on the primary and fallback channels. Primary: [{0}] Fallback: [{1}]".format(ustr(primary_channel_error), ustr(exception)))

    def upload_status_blob(self):
        extensions_goal_state = self.get_goal_state().extensions_goal_state

        if extensions_goal_state.status_upload_blob is None:
            # the status upload blob is in ExtensionsConfig so force a full goal state refresh
            self.reset_goal_state(silent=True)
            extensions_goal_state = self.get_goal_state().extensions_goal_state

            if extensions_goal_state.status_upload_blob is None:
                raise ProtocolNotFoundError("Status upload uri is missing")

            logger.info("Refreshed the goal state to get the status upload blob. New Goal State ID: {0}", extensions_goal_state.id)

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
        trans_cert_file = os.path.join(conf.get_lib_dir(), TRANSPORT_CERT_FILE_NAME)
        try:
            content = fileutil.read_file(trans_cert_file)
        except IOError as e:
            raise ProtocolError("Failed to read {0}: {1}".format(trans_cert_file, e))

        cert = get_bytes_from_pem(content)
        return {
            "x-ms-agent-name": "WALinuxAgent",
            "x-ms-version": PROTOCOL_VERSION,
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert": cert
        }

    def get_host_plugin(self):
        if self._host_plugin is None:
            self._host_plugin = HostPluginProtocol(self.get_endpoint())
            GoalState.update_host_plugin_headers(self)
        return self._host_plugin

    def get_on_hold(self):
        return self.get_goal_state().extensions_goal_state.on_hold

    def upload_logs(self, content):
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
