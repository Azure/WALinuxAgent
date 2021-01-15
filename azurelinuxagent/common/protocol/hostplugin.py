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
#

import base64
import datetime
import json
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.errorstate import ErrorState, ERROR_STATE_HOST_PLUGIN_FAILURE
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import HttpError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.textutil import remove_bom
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, PY_VERSION_MAJOR

HOST_PLUGIN_PORT = 32526

URI_FORMAT_GET_API_VERSIONS = "http://{0}:{1}/versions"
URI_FORMAT_GET_EXTENSION_ARTIFACT = "http://{0}:{1}/extensionArtifact"
URI_FORMAT_PUT_VM_STATUS = "http://{0}:{1}/status"
URI_FORMAT_PUT_LOG = "http://{0}:{1}/vmAgentLog"
URI_FORMAT_HEALTH = "http://{0}:{1}/health"

API_VERSION = "2015-09-01"

_HEADER_CLIENT_NAME = "x-ms-client-name"
_HEADER_CLIENT_VERSION = "x-ms-client-version"
_HEADER_CORRELATION_ID = "x-ms-client-correlationid"
_HEADER_CONTAINER_ID = "x-ms-containerid"
_HEADER_DEPLOYMENT_ID = "x-ms-vmagentlog-deploymentid"
_HEADER_VERSION = "x-ms-version"
_HEADER_HOST_CONFIG_NAME = "x-ms-host-config-name"
_HEADER_ARTIFACT_LOCATION = "x-ms-artifact-location"
_HEADER_ARTIFACT_MANIFEST_LOCATION = "x-ms-artifact-manifest-location"

MAXIMUM_PAGEBLOB_PAGE_SIZE = 4 * 1024 * 1024  # Max page size: 4MB


class HostPluginProtocol(object): # pylint: disable=R0902
    _is_default_channel = False

    FETCH_REPORTING_PERIOD = datetime.timedelta(minutes=1)
    STATUS_REPORTING_PERIOD = datetime.timedelta(minutes=1)

    def __init__(self, endpoint, container_id, role_config_name):
        if endpoint is None:
            raise ProtocolError("HostGAPlugin: Endpoint not provided")
        self.is_initialized = False
        self.is_available = False
        self.api_versions = None
        self.endpoint = endpoint
        self.container_id = container_id
        self.deployment_id = self._extract_deployment_id(role_config_name)
        self.role_config_name = role_config_name
        self.manifest_uri = None
        self.health_service = HealthService(endpoint)
        self.fetch_error_state = ErrorState(min_timedelta=ERROR_STATE_HOST_PLUGIN_FAILURE)
        self.status_error_state = ErrorState(min_timedelta=ERROR_STATE_HOST_PLUGIN_FAILURE)
        self.fetch_last_timestamp = None
        self.status_last_timestamp = None

    @staticmethod
    def _extract_deployment_id(role_config_name):
        # Role config name consists of: <deployment id>.<incarnation>(...)
        return role_config_name.split(".")[0] if role_config_name is not None else None

    @staticmethod
    def is_default_channel():
        return HostPluginProtocol._is_default_channel

    @staticmethod
    def set_default_channel(is_default):
        HostPluginProtocol._is_default_channel = is_default

    def update_container_id(self, new_container_id):
        self.container_id = new_container_id

    def update_role_config_name(self, new_role_config_name):
        self.role_config_name = new_role_config_name
        self.deployment_id = self._extract_deployment_id(new_role_config_name)

    def update_manifest_uri(self, new_manifest_uri):
        self.manifest_uri = new_manifest_uri

    def ensure_initialized(self):
        if not self.is_initialized:
            self.api_versions = self.get_api_versions()
            self.is_available = API_VERSION in self.api_versions
            self.is_initialized = self.is_available
            add_event(WALAEventOperation.InitializeHostPlugin,
                      is_success=self.is_available)
        return self.is_available

    def get_health(self):
        """
        Call the /health endpoint
        :return: True if 200 received, False otherwise
        """
        url = URI_FORMAT_HEALTH.format(self.endpoint,
                                       HOST_PLUGIN_PORT)
        logger.verbose("HostGAPlugin: Getting health from [{0}]", url)
        response = restutil.http_get(url, max_retry=1)
        return restutil.request_succeeded(response)

    def get_api_versions(self):
        url = URI_FORMAT_GET_API_VERSIONS.format(self.endpoint,
                                                 HOST_PLUGIN_PORT)
        logger.verbose("HostGAPlugin: Getting API versions at [{0}]"
                       .format(url))
        return_val = []
        error_response = ''
        is_healthy = False
        try:
            headers = {_HEADER_CONTAINER_ID: self.container_id}
            response = restutil.http_get(url, headers)

            if restutil.request_failed(response):
                error_response = restutil.read_response_error(response)
                logger.error("HostGAPlugin: Failed Get API versions: {0}".format(error_response))
                is_healthy = not restutil.request_failed_at_hostplugin(response)
            else:
                return_val = ustr(remove_bom(response.read()), encoding='utf-8')
                is_healthy = True
        except HttpError as e: # pylint: disable=C0103
            logger.error("HostGAPlugin: Exception Get API versions: {0}".format(e))

        self.health_service.report_host_plugin_versions(is_healthy=is_healthy, response=error_response)

        return return_val

    def get_artifact_request(self, artifact_url, artifact_manifest_url=None):
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: Host plugin channel is not available")

        if textutil.is_str_none_or_whitespace(artifact_url):
            raise ProtocolError("HostGAPlugin: No extension artifact url was provided")

        url = URI_FORMAT_GET_EXTENSION_ARTIFACT.format(self.endpoint,
                                                       HOST_PLUGIN_PORT)
        headers = {_HEADER_VERSION: API_VERSION,
                   _HEADER_CONTAINER_ID: self.container_id,
                   _HEADER_HOST_CONFIG_NAME: self.role_config_name,
                   _HEADER_ARTIFACT_LOCATION: artifact_url}

        if artifact_manifest_url is not None:
            headers[_HEADER_ARTIFACT_MANIFEST_LOCATION] = artifact_manifest_url

        return url, headers

    def report_fetch_health(self, uri, is_healthy=True, source='', response=''):

        if uri != URI_FORMAT_GET_EXTENSION_ARTIFACT.format(self.endpoint, HOST_PLUGIN_PORT):
            return

        if self.should_report(is_healthy,
                              self.fetch_error_state,
                              self.fetch_last_timestamp,
                              HostPluginProtocol.FETCH_REPORTING_PERIOD):
            self.fetch_last_timestamp = datetime.datetime.utcnow()
            health_signal = self.fetch_error_state.is_triggered() is False
            self.health_service.report_host_plugin_extension_artifact(is_healthy=health_signal,
                                                                      source=source,
                                                                      response=response)

    def report_status_health(self, is_healthy, response=''):
        if self.should_report(is_healthy,
                              self.status_error_state,
                              self.status_last_timestamp,
                              HostPluginProtocol.STATUS_REPORTING_PERIOD):
            self.status_last_timestamp = datetime.datetime.utcnow()
            health_signal = self.status_error_state.is_triggered() is False
            self.health_service.report_host_plugin_status(is_healthy=health_signal,
                                                          response=response)

    @staticmethod
    def should_report(is_healthy, error_state, last_timestamp, period):
        """
        Determine whether a health signal should be reported
        :param is_healthy: whether the current measurement is healthy
        :param error_state: the error state which is tracking time since failure
        :param last_timestamp: the last measurement time stamp
        :param period: the reporting period
        :return: True if the signal should be reported, False otherwise
        """

        if is_healthy:
            # we only reset the error state upon success, since we want to keep
            # reporting the failure; this is different to other uses of error states
            # which do not have a separate periodicity
            error_state.reset()
        else:
            error_state.incr()

        if last_timestamp is None:
            last_timestamp = datetime.datetime.utcnow() - period

        return datetime.datetime.utcnow() >= (last_timestamp + period)

    def put_vm_log(self, content):
        """
        Try to upload VM logs, a compressed zip file, via the host plugin /vmAgentLog channel.
        :param content: the binary content of the zip file to upload
        """
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: HostGAPlugin is not available")

        if content is None:
            raise ProtocolError("HostGAPlugin: Invalid argument passed to upload VM logs. Content was not provided.")

        url = URI_FORMAT_PUT_LOG.format(self.endpoint, HOST_PLUGIN_PORT)
        response = restutil.http_put(url,
                                     data=content,
                                     headers=self._build_log_headers(),
                                     redact_data=True)

        if restutil.request_failed(response): # pylint: disable=R1720
            error_response = restutil.read_response_error(response)
            raise HttpError("HostGAPlugin: Upload VM logs failed: {0}".format(error_response))

        return response

    def put_vm_status(self, status_blob, sas_url, config_blob_type=None):
        """
        Try to upload the VM status via the host plugin /status channel
        :param sas_url: the blob SAS url to pass to the host plugin
        :param config_blob_type: the blob type from the extension config
        :type status_blob: StatusBlob
        """
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: HostGAPlugin is not available")

        if status_blob is None or status_blob.vm_status is None:
            raise ProtocolError("HostGAPlugin: Status blob was not provided")

        logger.verbose("HostGAPlugin: Posting VM status")
        blob_type = status_blob.type if status_blob.type else config_blob_type

        if blob_type == "BlockBlob":
            self._put_block_blob_status(sas_url, status_blob)
        else:
            self._put_page_blob_status(sas_url, status_blob)

    def _put_block_blob_status(self, sas_url, status_blob):
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)

        response = restutil.http_put(url,
                                     data=self._build_status_data(
                                         sas_url,
                                         status_blob.get_block_blob_headers(len(status_blob.data)),
                                         bytearray(status_blob.data, encoding='utf-8')),
                                     headers=self._build_status_headers())

        if restutil.request_failed(response): # pylint: disable=R1720
            error_response = restutil.read_response_error(response)
            is_healthy = not restutil.request_failed_at_hostplugin(response)
            self.report_status_health(is_healthy=is_healthy, response=error_response)
            raise HttpError("HostGAPlugin: Put BlockBlob failed: {0}"
                            .format(error_response))
        else:
            self.report_status_health(is_healthy=True)
            logger.verbose("HostGAPlugin: Put BlockBlob status succeeded")

    def _put_page_blob_status(self, sas_url, status_blob):
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)

        # Convert the status into a blank-padded string whose length is modulo 512
        status = bytearray(status_blob.data, encoding='utf-8')
        status_size = int((len(status) + 511) / 512) * 512
        status = bytearray(status_blob.data.ljust(status_size), encoding='utf-8')

        # First, initialize an empty blob
        response = restutil.http_put(url,
                                     data=self._build_status_data(
                                         sas_url,
                                         status_blob.get_page_blob_create_headers(status_size)),
                                     headers=self._build_status_headers())

        if restutil.request_failed(response): # pylint: disable=R1720
            error_response = restutil.read_response_error(response)
            is_healthy = not restutil.request_failed_at_hostplugin(response)
            self.report_status_health(is_healthy=is_healthy, response=error_response)
            raise HttpError("HostGAPlugin: Failed PageBlob clean-up: {0}"
                            .format(error_response))
        else:
            self.report_status_health(is_healthy=True)
            logger.verbose("HostGAPlugin: PageBlob clean-up succeeded")
        
        # Then, upload the blob in pages
        if sas_url.count("?") <= 0:
            sas_url = "{0}?comp=page".format(sas_url)
        else:
            sas_url = "{0}&comp=page".format(sas_url)

        start = 0
        end = 0
        while start < len(status):
            # Create the next page
            end = start + min(len(status) - start, MAXIMUM_PAGEBLOB_PAGE_SIZE)
            page_size = int((end - start + 511) / 512) * 512
            buf = bytearray(page_size)
            buf[0: end - start] = status[start: end]

            # Send the page
            response = restutil.http_put(url,
                                         data=self._build_status_data(
                                             sas_url,
                                             status_blob.get_page_blob_page_headers(start, end),
                                             buf),
                                         headers=self._build_status_headers())

            if restutil.request_failed(response):
                error_response = restutil.read_response_error(response)
                is_healthy = not restutil.request_failed_at_hostplugin(response)
                self.report_status_health(is_healthy=is_healthy, response=error_response)
                raise HttpError(
                    "HostGAPlugin Error: Put PageBlob bytes "
                    "[{0},{1}]: {2}".format(start, end, error_response))

            # Advance to the next page (if any)
            start = end
        
    def _build_status_data(self, sas_url, blob_headers, content=None):
        headers = []
        for name in iter(blob_headers.keys()):
            headers.append({
                'headerName': name,
                'headerValue': blob_headers[name]
            })

        data = {
            'requestUri': sas_url,
            'headers': headers
        }
        if not content is None:
            data['content'] = self._base64_encode(content)
        return json.dumps(data, sort_keys=True)
    
    def _build_status_headers(self):
        return {
            _HEADER_VERSION: API_VERSION,
            "Content-type": "application/json",
            _HEADER_CONTAINER_ID: self.container_id,
            _HEADER_HOST_CONFIG_NAME: self.role_config_name
        }

    def _build_log_headers(self):
        return {
            _HEADER_VERSION: API_VERSION,
            _HEADER_CONTAINER_ID: self.container_id,
            _HEADER_DEPLOYMENT_ID: self.deployment_id,
            _HEADER_CLIENT_NAME: AGENT_NAME,
            _HEADER_CLIENT_VERSION: AGENT_VERSION,
            _HEADER_CORRELATION_ID: str(uuid.uuid4())
        }

    def _base64_encode(self, data):
        s = base64.b64encode(bytes(data)) # pylint: disable=C0103
        if PY_VERSION_MAJOR > 2:
            return s.decode('utf-8')
        return s
