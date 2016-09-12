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
import os
import shutil
import re
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.protocol.restapi import *
from azurelinuxagent.common.utils.cryptutil import CryptUtil

METADATA_ENDPOINT = '169.254.169.254'
APIVERSION = '2015-05-01-preview'
BASE_URI = "http://{0}/Microsoft.Compute/{1}?api-version={2}{3}"

TRANSPORT_PRV_FILE_NAME = "V2TransportPrivate.pem"
TRANSPORT_CERT_FILE_NAME = "V2TransportCert.pem"
P7M_FILE_NAME = "Certificates.p7m"
P7B_FILE_NAME = "Certificates.p7b"
PEM_FILE_NAME = "Certificates.pem"

# TODO remote workaround for azure stack
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
        self.certs = None

    def _get_data(self, url, headers=None):
        try:
            resp = restutil.http_get(url, headers=headers)
        except HttpError as e:
            raise ProtocolError(ustr(e))

        if resp.status != httpclient.OK:
            raise ProtocolError("{0} - GET: {1}".format(resp.status, url))

        data = resp.read()
        etag = resp.getheader('ETag')
        if data is not None:
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

        # "Install" the cert and private key to /var/lib/waagent
        thumbprint = cryptutil.get_thumbprint_from_crt(trans_cert_file)
        prv_file = os.path.join(conf.get_lib_dir(),
                                "{0}.prv".format(thumbprint))
        crt_file = os.path.join(conf.get_lib_dir(),
                                "{0}.crt".format(thumbprint))
        shutil.copyfile(trans_prv_file, prv_file)
        shutil.copyfile(trans_cert_file, crt_file)
        self.update_goal_state(forced=True)

    def get_vminfo(self):
        vminfo = VMInfo()
        data, etag = self._get_data(self.identity_uri)
        set_properties("vminfo", vminfo, data)
        return vminfo

    def get_certs(self):
        certlist = CertList()
        certificatedata = CertificateData()
        data, etag = self._get_data(self.cert_uri)

        set_properties("certlist", certlist, data)

        cert_list = get_properties(certlist)

        headers = {
            "x-ms-vmagent-public-x509-cert": self._get_trans_cert()
        }

        for cert_i in cert_list["certificates"]:
            certificate_data_uri = cert_i['certificateDataUri']
            data, etag = self._get_data(certificate_data_uri, headers=headers)
            set_properties("certificatedata", certificatedata, data)
            json_certificate_data = get_properties(certificatedata)

            self.certs = Certificates(self, json_certificate_data)

        if self.certs is None:
            return None
        return self.certs

    def get_vmagent_manifests(self, last_etag=None):
        manifests = VMAgentManifestList()
        self.update_goal_state()
        data, etag = self._get_data(self.vmagent_uri)
        if last_etag is None or last_etag < etag:
            set_properties("vmAgentManifests",
                           manifests.vmAgentManifests,
                           data)
        return manifests, etag

    def get_vmagent_pkgs(self, vmagent_manifest):
        # Agent package is the same with extension handler
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
        # TODO: What etag should this return?
        return vmagent_pkgs

    def get_ext_handlers(self, last_etag=None):
        self.update_goal_state()
        headers = {
            "x-ms-vmagent-public-x509-cert": self._get_trans_cert()
        }
        ext_list = ExtHandlerList()
        data, etag = self._get_data(self.ext_uri, headers=headers)
        if last_etag is None or last_etag < etag:
            set_properties("extensionHandlers", ext_list.extHandlers, data)
        return ext_list, etag

    def get_ext_handler_pkgs(self, ext_handler):
        logger.info("Get extension handler packages")
        pkg_list = ExtHandlerPackageList()

        manifest = None
        for version_uri in ext_handler.versionUris:
            try:
                manifest, etag = self._get_data(version_uri.uri)
                logger.info("Successfully downloaded manifest")
                break
            except ProtocolError as e:
                logger.warn("Failed to fetch manifest: {0}", e)

        if manifest is None:
            raise ValueError("Extension manifest is empty")

        # todo: parse manifest

        set_properties("extensionPackages", pkg_list, manifest)

        return pkg_list

    def report_provision_status(self, provision_status):
        validate_param('provisionStatus', provision_status, ProvisionStatus)
        data = get_properties(provision_status)
        self._put_data(self.provision_status_uri, data)

    def report_vm_status(self, vm_status):
        validate_param('vmStatus', vm_status, VMStatus)
        data = get_properties(vm_status)
        # TODO code field is not implemented for metadata protocol yet.
        # Remove it
        handler_statuses = data['vmAgent']['extensionHandlers']
        for handler_status in handler_statuses:
            try:
                handler_status.pop('code', None)
            except KeyError:
                pass

        self._put_data(self.vm_status_uri, data)

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        validate_param('extensionStatus', ext_status, ExtensionStatus)
        data = get_properties(ext_status)
        uri = self.ext_status_uri.format(ext_name)
        self._put_data(uri, data)

    def report_event(self, events):
        # TODO disable telemetry for azure stack test
        # validate_param('events', events, TelemetryEventList)
        # data = get_properties(events)
        # self._post_data(self.event_uri, data)
        pass

    def update_certs(self):
        logger.info("Inside MetadataClient.update_certs")
        certificates = self.get_certs()
        return certificates.cert_list

    def update_goal_state(self, forced=False, max_retry=3):
        logger.info("Inside update_goal_state")
        # Start updating goalstate, retry on 410
        for retry in range(0, max_retry):
            try:
                self.update_certs()
                return
            except:
                logger.info("Incarnation is out of date. Update goalstate.")

        raise ProtocolError("Exceeded max retry updating goal state")


class Certificates(object):
    """
    Object containing certificates of host and provisioned user.
    """

    def __init__(self, client, json_text):
        self.cert_list = CertList()
        self.parse(json_text)

    def parse(self, json_text):
        """
        Parse multiple certificates into seperate files.
        """

        data = json_text["certificateData"]
        if data is None:
            logger.verbose("No data in json_text received!")
            return

        cryptutil = CryptUtil(conf.get_openssl_cmd())
        p7b_file = os.path.join(conf.get_lib_dir(), P7B_FILE_NAME)

        # Wrapping the certificate lines.
        b64_cmd = "echo {0} | base64 -d > {1}"
        shellutil.run(b64_cmd.format(data, p7b_file))
        ssl_cmd = "openssl pkcs7 -text -in {0} -inform der | grep -v '^-----' "
        ret, data = shellutil.run_get_output(ssl_cmd.format(p7b_file))

        p7m_file = os.path.join(conf.get_lib_dir(), P7M_FILE_NAME)
        p7m = ("MIME-Version:1.0\n"
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(p7m_file, p7m_file, data)

        self.save_cache(p7m_file, p7m)

        trans_prv_file = os.path.join(conf.get_lib_dir(),
                                      TRANSPORT_PRV_FILE_NAME)
        trans_cert_file = os.path.join(conf.get_lib_dir(),
                                       TRANSPORT_CERT_FILE_NAME)
        pem_file = os.path.join(conf.get_lib_dir(), PEM_FILE_NAME)
        # decrypt certificates
        cryptutil.decrypt_p7m(p7m_file, trans_prv_file, trans_cert_file,
                              pem_file)

        # The parsing process use public key to match prv and crt.
        buf = []
        begin_crt = False
        begin_prv = False
        prvs = {}
        thumbprints = {}
        index = 0
        v1_cert_list = []
        with open(pem_file) as pem:
            for line in pem.readlines():
                buf.append(line)
                if re.match(r'[-]+BEGIN.*KEY[-]+', line):
                    begin_prv = True
                elif re.match(r'[-]+BEGIN.*CERTIFICATE[-]+', line):
                    begin_crt = True
                elif re.match(r'[-]+END.*KEY[-]+', line):
                    tmp_file = self.write_to_tmp_file(index, 'prv', buf)
                    pub = cryptutil.get_pubkey_from_prv(tmp_file)
                    prvs[pub] = tmp_file
                    buf = []
                    index += 1
                    begin_prv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmp_file = self.write_to_tmp_file(index, 'crt', buf)
                    pub = cryptutil.get_pubkey_from_crt(tmp_file)
                    thumbprint = cryptutil.get_thumbprint_from_crt(tmp_file)
                    thumbprints[pub] = thumbprint
                    # Rename crt with thumbprint as the file name
                    crt = "{0}.crt".format(thumbprint)
                    v1_cert_list.append({
                        "name": None,
                        "thumbprint": thumbprint
                    })
                    os.rename(tmp_file, os.path.join(conf.get_lib_dir(), crt))
                    buf = []
                    index += 1
                    begin_crt = False

        # Rename prv key with thumbprint as the file name
        for pubkey in prvs:
            thumbprint = thumbprints[pubkey]
            if thumbprint:
                tmp_file = prvs[pubkey]
                prv = "{0}.prv".format(thumbprint)
                os.rename(tmp_file, os.path.join(conf.get_lib_dir(), prv))

        for v1_cert in v1_cert_list:
            cert = Cert()
            set_properties("certs", cert, v1_cert)
            self.cert_list.certificates.append(cert)

    def save_cache(self, local_file, data):
        try:
            fileutil.write_file(local_file, data)
        except IOError as e:
            raise ProtocolError("Failed to write cache: {0}".format(e))

    def write_to_tmp_file(self, index, suffix, buf):
        file_name = os.path.join(conf.get_lib_dir(),
                                 "{0}.{1}".format(index, suffix))
        self.save_cache(file_name, "".join(buf))
        return file_name
