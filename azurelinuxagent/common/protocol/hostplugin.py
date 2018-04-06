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
import json
import traceback

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import HttpError, ProtocolError, \
                                            ResourceGoneError
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.textutil import remove_bom
from azurelinuxagent.common.version import PY_VERSION_MAJOR

HOST_PLUGIN_PORT = 32526
URI_FORMAT_GET_API_VERSIONS = "http://{0}:{1}/versions"
URI_FORMAT_GET_EXTENSION_ARTIFACT = "http://{0}:{1}/extensionArtifact"
URI_FORMAT_PUT_VM_STATUS = "http://{0}:{1}/status"
URI_FORMAT_PUT_LOG = "http://{0}:{1}/vmAgentLog"
API_VERSION = "2015-09-01"
HEADER_CONTAINER_ID = "x-ms-containerid"
HEADER_VERSION = "x-ms-version"
HEADER_HOST_CONFIG_NAME = "x-ms-host-config-name"
HEADER_ARTIFACT_LOCATION = "x-ms-artifact-location"
HEADER_ARTIFACT_MANIFEST_LOCATION = "x-ms-artifact-manifest-location"
MAXIMUM_PAGEBLOB_PAGE_SIZE = 4 * 1024 * 1024  # Max page size: 4MB


class HostPluginProtocol(object):
    _is_default_channel = False

    def __init__(self, endpoint, container_id, role_config_name):
        if endpoint is None:
            raise ProtocolError("HostGAPlugin: Endpoint not provided")
        self.is_initialized = False
        self.is_available = False
        self.api_versions = None
        self.endpoint = endpoint
        self.container_id = container_id
        self.deployment_id = None
        self.role_config_name = role_config_name
        self.manifest_uri = None

    @staticmethod
    def is_default_channel():
        return HostPluginProtocol._is_default_channel

    @staticmethod
    def set_default_channel(is_default):
        HostPluginProtocol._is_default_channel = is_default

    def ensure_initialized(self):
        if not self.is_initialized:
            self.api_versions = self.get_api_versions()
            self.is_available = API_VERSION in self.api_versions
            self.is_initialized = self.is_available
            from azurelinuxagent.common.event import WALAEventOperation, report_event
            report_event(WALAEventOperation.InitializeHostPlugin,
                         is_success=self.is_available)
        return self.is_available

    def get_api_versions(self):
        url = URI_FORMAT_GET_API_VERSIONS.format(self.endpoint,
                                                 HOST_PLUGIN_PORT)
        logger.verbose("HostGAPlugin: Getting API versions at [{0}]".format(
            url))
        return_val = []
        try:
            headers = {HEADER_CONTAINER_ID: self.container_id}
            response = restutil.http_get(url, headers)
            if restutil.request_failed(response):
                logger.error(
                    "HostGAPlugin: Failed Get API versions: {0}".format(
                        restutil.read_response_error(response)))
            else:
                return_val = ustr(remove_bom(response.read()), encoding='utf-8')

        except HttpError as e:
            logger.error("HostGAPlugin: Exception Get API versions: {0}".format(e))

        return return_val

    def get_artifact_request(self, artifact_url, artifact_manifest_url=None):
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: Host plugin channel is not available")

        if textutil.is_str_none_or_whitespace(artifact_url):
            raise ProtocolError("HostGAPlugin: No extension artifact url was provided")

        url = URI_FORMAT_GET_EXTENSION_ARTIFACT.format(self.endpoint,
                                                       HOST_PLUGIN_PORT)
        headers = {HEADER_VERSION: API_VERSION,
                   HEADER_CONTAINER_ID: self.container_id,
                   HEADER_HOST_CONFIG_NAME: self.role_config_name,
                   HEADER_ARTIFACT_LOCATION: artifact_url}

        if artifact_manifest_url is not None:
            headers[HEADER_ARTIFACT_MANIFEST_LOCATION] = artifact_manifest_url

        return url, headers

    def put_vm_log(self, content):
        raise NotImplementedError("Unimplemented")

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
        try:

            blob_type = status_blob.type if status_blob.type else config_blob_type

            if blob_type == "BlockBlob":
                self._put_block_blob_status(sas_url, status_blob)
            else:
                self._put_page_blob_status(sas_url, status_blob)

        except Exception as e:
            # If the HostPlugin rejects the request,
            # let the error continue, but set to use the HostPlugin
            if isinstance(e, ResourceGoneError):
                logger.verbose("HostGAPlugin: Setting host plugin as default channel")
                HostPluginProtocol.set_default_channel(True)

            raise

    def _put_block_blob_status(self, sas_url, status_blob):
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)

        response = restutil.http_put(url,
                        data=self._build_status_data(
                                    sas_url,
                                    status_blob.get_block_blob_headers(len(status_blob.data)),
                                    bytearray(status_blob.data, encoding='utf-8')),
                        headers=self._build_status_headers())

        if restutil.request_failed(response):
            raise HttpError("HostGAPlugin: Put BlockBlob failed: {0}".format(
                restutil.read_response_error(response)))
        else:
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

        if restutil.request_failed(response):
            raise HttpError(
                "HostGAPlugin: Failed PageBlob clean-up: {0}".format(
                    restutil.read_response_error(response)))
        else:
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
                raise HttpError(
                    "HostGAPlugin Error: Put PageBlob bytes [{0},{1}]: " \
                    "{2}".format(
                        start, end, restutil.read_response_error(response)))

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
            HEADER_VERSION: API_VERSION,
            "Content-type": "application/json",
            HEADER_CONTAINER_ID: self.container_id,
            HEADER_HOST_CONFIG_NAME: self.role_config_name
        }
    
    def _base64_encode(self, data):
        s = base64.b64encode(bytes(data))
        if PY_VERSION_MAJOR > 2:
            return s.decode('utf-8')
        return s
