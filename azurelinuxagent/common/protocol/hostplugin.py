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
#

from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.utils import textutil

HOST_PLUGIN_PORT = 32526
URI_FORMAT_GET_API_VERSIONS = "http://{0}:{1}/versions"
URI_FORMAT_PUT_VM_STATUS = "http://{0}:{1}/status"
URI_FORMAT_PUT_LOG = "http://{0}:{1}/vmAgentLog"
API_VERSION = "2015-09-01"


class HostPluginProtocol(object):
    def __init__(self, endpoint):
        if endpoint is None:
            raise ProtocolError("Host plugin endpoint not provided")
        self.is_initialized = False
        self.is_available = False
        self.api_versions = None
        self.endpoint = endpoint

    def ensure_initialized(self):
        if not self.is_initialized:
            self.api_versions = self.get_api_versions()
            self.is_available = API_VERSION in self.api_versions
            self.is_initialized = True
        return self.is_available

    def get_api_versions(self):
        url = URI_FORMAT_GET_API_VERSIONS.format(self.endpoint,
                                                 HOST_PLUGIN_PORT)
        logger.info("getting API versions at [{0}]".format(url))
        try:
            response = restutil.http_get(url)
            if response.status != httpclient.OK:
                logger.error(
                    "get API versions returned status code [{0}]".format(
                        response.status))
                return []
            return response.read()
        except HttpError as e:
            logger.error("get API versions failed with [{0}]".format(e))
            return []

    def put_vm_status(self, status_blob, sas_url):
        """
        Try to upload the VM status via the host plugin /status channel
        :param sas_url: the blob SAS url to pass to the host plugin
        :type status_blob: StatusBlob
        """
        if not self.ensure_initialized():
            logger.error("host plugin channel is not available")
            return
        if status_blob is None or status_blob.vm_status is None:
            logger.error("no status data was provided")
            return
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)
        status = textutil.b64encode(status_blob.vm_status)
        headers = {"x-ms-version": API_VERSION}
        blob_headers = [{'headerName': 'x-ms-version',
                         'headerValue': status_blob.__storage_version__},
                        {'headerName': 'x-ms-blob-type',
                         'headerValue': status_blob.type}]
        data = json.dumps({'requestUri': sas_url, 'headers': blob_headers,
                           'content': status}, sort_keys=True)
        logger.info("put VM status at [{0}]".format(url))
        try:
            response = restutil.http_put(url, data, headers)
            if response.status != httpclient.OK:
                logger.error("put VM status returned status code [{0}]".format(
                    response.status))
        except HttpError as e:
            logger.error("put VM status failed with [{0}]".format(e))

    def put_vm_log(self, content, container_id, deployment_id):
        """
        Try to upload the given content to the host plugin
        :param deployment_id: the deployment id, which is obtained from the
        goal state (tenant name)
        :param container_id: the container id, which is obtained from the
        goal state
        :param content: the binary content of the zip file to upload
        :return:
        """
        if not self.ensure_initialized():
            logger.error("host plugin channel is not available")
            return
        if content is None or container_id is None or deployment_id is None:
            logger.error(
                "invalid arguments passed: "
                "[{0}], [{1}], [{2}]".format(
                    content,
                    container_id,
                    deployment_id))
            return
        url = URI_FORMAT_PUT_LOG.format(self.endpoint, HOST_PLUGIN_PORT)

        headers = {"x-ms-vmagentlog-deploymentid": deployment_id,
                   "x-ms-vmagentlog-containerid": container_id}
        logger.info("put VM log at [{0}]".format(url))
        try:
            response = restutil.http_put(url, content, headers)
            if response.status != httpclient.OK:
                logger.error("put log returned status code [{0}]".format(
                    response.status))
        except HttpError as e:
            logger.error("put log failed with [{0}]".format(e))
