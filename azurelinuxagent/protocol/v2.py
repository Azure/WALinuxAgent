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

import httplib
import json
import azurelinuxagent.utils.restutil as restutil
from azurelinuxagent.protocol.common import *

DefaultEndpoint='169.254.169.254'
DefaultApiVersion='2015-01-01'
BaseUri = "https://{0}/Microsoft.Computer/{1}?$api-version={{{2}}}{3}" 

class ProtocolV2(Protocol):

    def __init__(self, apiVersion=DefaultApiVersion, endpoint=DefaultEndpoint):
        self.apiVersion = apiVersion
        self.endpoint = endpoint
        self.identityUri = BaseUri.format(self.endpoint, "identity",
                                          self.apiVersion, "&expand=*")
        self.certUri = BaseUri.format(self.endpoint, "certificates",
                                      self.apiVersion, "&expand=*")
        self.certUri = BaseUri.format(self.endpoint, "certificates",
                                      self.apiVersion, "&expand=*")
        self.extUri = BaseUri.format(self.endpoint, "extensionHandlers",
                                     self.apiVersion, "&expand=*")
        self.provisionStatusUri = BaseUri.format(self.endpoint, 
                                                 "provisionStatus",
                                                 self.apiVersion, "")
        self.statusUri = BaseUri.format(self.endpoint, "status",
                                        self.apiVersion, "")
        self.eventUri = BaseUri.format(self.endpoint, "status/telemetry",
                                       self.apiVersion, "")

    def _getData(self, dataType, url, headers=None):
        try:
            resp = restutil.HttpGet(url, headers)
        except restutil.HttpError as e:
            raise ProtocolError(str(e))

        if resp.status != httplib.OK:
            raise ProtocolError("{0} - GET: {1}".format(resp.status, url))
        try:
            data = json.loads(resp.read())
        except ValueError as e:
            raise ProtocolError(str(e))
        obj = dataType()
        set_properties(obj, data)
        return obj

    def _putData(self, url, obj, headers=None):
        data = get_properties(obj)
        try:
            resp = restutil.HttpPut(url, json.dumps(data))
        except restutil.HttpError as e:
            raise ProtocolError(str(e))
        if resp.status != httplib.OK:
            raise ProtocolError("{0} - PUT: {1}".format(resp.status, url))

    def _postData(self, url, obj, headers=None):
        data = get_properties(obj)
        try:
            resp = restutil.HttpPost(url, json.dumps(data))
        except restutil.HttpError as e:
            raise ProtocolError(str(e))
        if resp.status != httplib.CREATED:
            raise ProtocolError("{0} - POST: {1}".format(resp.status, url))

    def initialize(self):
        pass
        
    def getVmInfo(self):
        return self._getData(VmInfo, self.identityUri)

    def getCerts(self):
        certs = self._getData(CertList, self.certUri)
        #TODO download pfx and convert to pem
        return certs

    def getExtensions(self):
        return self._getData(ExtensionList, self.extUri)

    def reportProvisionStatus(self, status):
        validata_param('status', status, ProvisionStatus)
        self._putData(self.provisionStatusUri, status)
        
    def reportStatus(self, status):
        validata_param('status', status, VMStatus)
        self._putData(self.statusUri, status)
    
    def reportEvent(self, events):
        validata_param('events', events, TelemetryEventList)
        self._postData(self.eventUri, events)

