# Windows Azure Linux Agent
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
from azurelinuxagent.future import httpclient, text
import azurelinuxagent.utils.restutil as restutil
from azurelinuxagent.protocol.common import *

ENDPOINT='169.254.169.254'
#TODO use http for azure pack test
#ENDPOINT='localhost'
APIVERSION='2015-05-01-preview'
BASE_URI = "http://{0}/Microsoft.Compute/{1}?api-version={{{2}}}{3}"

def _add_content_type(headers):
    if headers is None:
        headers = {}
    headers["content-type"] = "application/json"
    return headers

class MetadataProtocol(Protocol):

    def __init__(self, apiversion=APIVERSION, endpoint=ENDPOINT):
        self.apiversion = apiversion
        self.endpoint = endpoint
        self.identity_uri = BASE_URI.format(self.endpoint, "identity",
                                            self.apiversion, "&$expand=*")
        self.cert_uri = BASE_URI.format(self.endpoint, "certificates",
                                        self.apiversion, "&$expand=*")
        self.ext_uri = BASE_URI.format(self.endpoint, "extensionHandlers",
                                       self.apiversion, "&$expand=*")
        self.provision_status_uri = BASE_URI.format(self.endpoint,
                                                    "provisioningStatus",
                                                    self.apiversion, "")
        self.status_uri = BASE_URI.format(self.endpoint, "status",
                                          self.apiversion, "")
        self.event_uri = BASE_URI.format(self.endpoint, "status/telemetry",
                                         self.apiversion, "")

    def _get_data(self, data_type, url, headers=None):
        try:
            resp = restutil.http_get(url, headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))

        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - GET: {1}".format(resp.status, url))
        try:
            data = resp.read()
            if data is None:
                return None
            data = json.loads(text(data, encoding="utf-8"))
        except ValueError as e:
            raise ProtocolError(text(e))
        obj = data_type()
        set_properties(obj, data)
        return obj

    def _put_data(self, url, obj, headers=None):
        headers = _add_content_type(headers) 
        data = get_properties(obj)
        try:
            resp = restutil.http_put(url, json.dumps(data), headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))
        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - PUT: {1}".format(resp.status, url))

    def _post_data(self, url, obj, headers=None):
        headers = _add_content_type(headers) 
        data = get_properties(obj)
        try:
            resp = restutil.http_post(url, json.dumps(data), headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))
        if resp.status != httpclient.CREATED:
            raise ProtocolError("{0} - POST: {1}".format(resp.status, url))

    def initialize(self):
        pass

    def get_vminfo(self):
        return self._get_data(VMInfo, self.identity_uri)

    def get_certs(self):
        #TODO walk arround for azure pack test
        return CertList()

        certs = self._get_data(CertList, self.cert_uri)
        #TODO download pfx and convert to pem
        return certs

    def get_extensions(self):
        return self._get_data(ExtensionList, self.ext_uri)

    def report_provision_status(self, status):
        validata_param('status', status, ProvisionStatus)
        self._put_data(self.provision_status_uri, status)

    def report_status(self, status):
        validata_param('status', status, VMStatus)
        self._put_data(self.status_uri, status)

    def report_event(self, events):
        validata_param('events', events, TelemetryEventList)
        self._post_data(self.event_uri, events)

