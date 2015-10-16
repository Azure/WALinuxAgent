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
import shutil
import os
from azurelinuxagent.utils.osutil import OSUTIL
from azurelinuxagent.future import httpclient, text
import azurelinuxagent.utils.restutil as restutil
import azurelinuxagent.utils.textutil as textutil
from azurelinuxagent.protocol.common import *

ENDPOINT='169.254.169.254'
#TODO use http for azure pack test
#ENDPOINT='localhost'
APIVERSION='2015-05-01-preview'
BASE_URI = "http://{0}/Microsoft.Compute/{1}?api-version={2}{3}"

TRANSPORT_PRV_FILE_NAME = "V2TransportCert.pem"
TRANSPORT_CERT_FILE_NAME = "V2TransportPrivate.pem"

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
        self.vm_status_uri = BASE_URI.format(self.endpoint, "status/vmagent",
                                             self.apiversion, "")
        self.ext_status_uri = BASE_URI.format(self.endpoint, 
                                              "status/extensions/{0}",
                                              self.apiversion, "")
        self.event_uri = BASE_URI.format(self.endpoint, "status/telemetry",
                                         self.apiversion, "")

    def _get_data(self, url, headers=None):
        try:
            resp = restutil.http_get(url, headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))

        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - GET: {1}".format(resp.status, url))

        data = resp.read()
        if data is None:
            return None
        data = json.loads(text(data, encoding="utf-8"))
        return data

    def _put_data(self, url, data, headers=None):
        headers = _add_content_type(headers) 
        try:
            resp = restutil.http_put(url, json.dumps(data), headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))
        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - PUT: {1}".format(resp.status, url))

    def _post_data(self, url, data, headers=None):
        headers = _add_content_type(headers) 
        try:
            resp = restutil.http_post(url, json.dumps(data), headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError(text(e))
        if resp.status != httpclient.CREATED:
            raise ProtocolError("{0} - POST: {1}".format(resp.status, url))
    
    def _get_trans_cert(self):
        file_name = TRANSPORT_CERT_FILE_NAME
        if not os.path.isfile(file_name):
            raise ProtocolError("{0} is missing.".format(file_name))
        content = fileutil.read_file(file_name)
        return textutil.get_bytes_from_pem(content)

    def initialize(self):
        trans_prv_file = os.path.join(OSUTIL.get_lib_dir(), 
                                      TRANSPORT_PRV_FILE_NAME)
        trans_crt_file = os.path.join(OSUTIL.get_lib_dir(), 
                                      TRANSPORT_CERT_FILE_NAME)
        OSUTIL.gen_transport_cert(trans_prv_file, trans_crt_file)

        #"Install" the cert and private key to /var/lib/waagent
        thumbprint = OSUTIL.get_thumbprint_from_crt(trans_crt_file)
        prv_file = os.path.join(OSUTIL.get_lib_dir(), 
                                "{0}.prv".format(thumbprint))
        crt_file = os.path.join(OSUTIL.get_lib_dir(), 
                                "{0}.crt".format(thumbprint))
        shutil.copyfile(trans_prv_file, prv_file)
        shutil.copyfile(trans_crt_file, crt_file)

    def get_vminfo(self):
        vminfo = VMInfo()
        data = self._get_data(self.identity_uri)
        set_properties("vminfo", vminfo, data)
        return vminfo

    def get_certs(self):
        #TODO download and save certs
        return CertList()

    def get_ext_handlers(self):
        headers = {
            "x-ms-vmagent-public-x509-cert": self._get_trans_cert()
        }
        ext_list = ExtHandlerList()
        data = self._get_data(self.ext_uri, headers=headers)
        set_properties("extensionHandlers", ext_list.extHandlers, data)
        return ext_list

    def get_ext_handler_pkgs(self, ext_handler):
        ext_handler_pkgs = ExtHandlerPackageList()
        data = None
        for version_uri in ext_handler.versionUris:
            try:
                data = self._get_data(version_uri.uri)
                break
            except ProtocolError as e:
                logger.warn("Failed to get version uris: {0}", e)
                logger.info("Retry getting version uris")
        set_properties("extensionPackages", ext_handler_pkgs, data)
        return ext_handler_pkgs

    def report_provision_status(self, provision_status):
        validata_param('provisionStatus', provision_status, ProvisionStatus)
        data = get_properties(provision_status)
        self._put_data(self.provision_status_uri, data)

    def report_vm_status(self, vm_status):
        validata_param('vmStatus', vm_status, VMStatus)
        data = get_properties(vm_status)
        self._put_data(self.vm_status_uri, data)

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        validata_param('extensionStatus', ext_status, ExtensionStatus)
        data = get_properties(ext_status)
        uri = self.ext_status_uri.format(ext_name)
        self._put_data(uri, data)

    def report_event(self, events):
        #TODO disable telemetry for azure stack test
        #validata_param('events', events, TelemetryEventList)
        #data = get_properties(events)
        #self._post_data(self.event_uri, data)
        pass

