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
import time
from azurelinuxagent.common.exception import ProtocolError, HttpError
from azurelinuxagent.common.future import httpclient, ustr
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.textutil as textutil
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.protocol.restapi import *

METADATA_ENDPOINT='169.254.169.254'
APIVERSION='2015-05-01-preview'
BASE_URI = "http://{0}/Microsoft.Compute/{1}?api-version={2}{3}"

TRANSPORT_PRV_FILE_NAME = "V2TransportPrivate.pem"
TRANSPORT_CERT_FILE_NAME = "V2TransportCert.pem"

#TODO remote workarround for azure stack 
MAX_PING = 30
RETRY_PING_INTERVAL = 10

def _add_content_type(headers):
    if headers is None:
        headers = {}
    headers["content-type"] = "application/json"
    return headers

class MetadataProtocol(Protocol):

    def __init__(self, apiversion=APIVERSION, endpoint=METADATA_ENDPOINT):
        self.apiversion = apiversion
        self.endpoint = endpoint
        self.identity_uri = BASE_URI.format(self.endpoint, "identity",
                                            self.apiversion, "&$expand=*")
        self.cert_uri = BASE_URI.format(self.endpoint, "certificates",
                                        self.apiversion, "&$expand=*")
        self.ext_uri = BASE_URI.format(self.endpoint, "extensionHandlers",
                                       self.apiversion, "&$expand=*")
        self.vmagent_uri = BASE_URI.format(self.endpoint, "vmAgentVersions",
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
        except HttpError as e:
            raise ProtocolError(ustr(e))

        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - GET: {1}".format(resp.status, url))

        data = resp.read()
        etag = resp.getheader('ETag')
        if data is None:
            return None
        data = json.loads(ustr(data, encoding="utf-8"))
        return data, etag

    def _put_data(self, url, data, headers=None):
        headers = _add_content_type(headers) 
        try:
            resp = restutil.http_put(url, json.dumps(data), headers=headers)
        except HttpError as e:
            raise ProtocolError(ustr(e))
        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - PUT: {1}".format(resp.status, url))

    def _post_data(self, url, data, headers=None):
        headers = _add_content_type(headers) 
        try:
            resp = restutil.http_post(url, json.dumps(data), headers=headers)
        except HttpError as e:
            raise ProtocolError(ustr(e))
        if resp.status != httpclient.CREATED:
            raise ProtocolError("{0} - POST: {1}".format(resp.status, url))
    
    def _get_trans_cert(self):
        trans_crt_file = os.path.join(conf.get_lib_dir(), 
                                      TRANSPORT_CERT_FILE_NAME)
        if not os.path.isfile(trans_crt_file):
            raise ProtocolError("{0} is missing.".format(trans_crt_file))
        content = fileutil.read_file(trans_crt_file)
        return textutil.get_bytes_from_pem(content)

    def detect(self):
        self.get_vminfo()
        trans_prv_file = os.path.join(conf.get_lib_dir(), 
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(), 
                                       TRANSPORT_CERT_FILE_NAME)
        cryptutil = CryptUtil(conf.get_openssl_cmd())
        cryptutil.gen_transport_cert(trans_prv_file, trans_cert_file)

        #"Install" the cert and private key to /var/lib/waagent
        thumbprint = cryptutil.get_thumbprint_from_crt(trans_cert_file)
        prv_file = os.path.join(conf.get_lib_dir(), 
                                "{0}.prv".format(thumbprint))
        crt_file = os.path.join(conf.get_lib_dir(), 
                                "{0}.crt".format(thumbprint))
        shutil.copyfile(trans_prv_file, prv_file)
        shutil.copyfile(trans_cert_file, crt_file)


    def get_vminfo(self):
        vminfo = VMInfo()
        data, etag = self._get_data(self.identity_uri)
        set_properties("vminfo", vminfo, data)
        return vminfo

    def get_certs(self):
        #TODO download and save certs
        return CertList()

    def get_vmagent_manifests(self):
        manifests = VMAgentManifestList()
        data = self._get_data(self.vmagent_uri)
        set_properties("vmAgentManifests", manifests.vmAgentManifests, data)
        return manifests

    def get_vmagent_pkgs(self, vmagent_manifest):
        #Agent package is the same with extension handler
        vmagent_pkgs = ExtHandlerPackageList()
        data = None
        for manifest_uri in vmagent_manifest.versionsManifestUris:
            try:
                data = self._get_data(manifest_uri.uri)
                break
            except ProtocolError as e:
                logger.warn("Failed to get vmagent versions: {0}", e)
                logger.info("Retry getting vmagent versions")
        if data is None:
            raise ProtocolError(("Failed to get versions for vm agent: {0}"
                                 "").format(vmagent_manifest.family))
        set_properties("vmAgentVersions", vmagent_pkgs, data)
        return vmagent_pkgs

    def get_ext_handlers(self):
        headers = {
            "x-ms-vmagent-public-x509-cert": self._get_trans_cert()
        }
        ext_list = ExtHandlerList()
        data, etag = self._get_data(self.ext_uri, headers=headers)
        set_properties("extensionHandlers", ext_list.extHandlers, data)
        return ext_list, etag

    def get_ext_handler_pkgs(self, ext_handler):
        ext_handler_pkgs = ExtHandlerPackageList()
        data = None
        for version_uri in ext_handler.versionUris:
            try:
                data, etag = self._get_data(version_uri.uri)
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
        #TODO code field is not implemented for metadata protocol yet. Remove it
        handler_statuses = data['vmAgent']['extensionHandlers']
        for handler_status in handler_statuses:
            try:
                handler_status.pop('code', None)
            except KeyError:
                pass

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

