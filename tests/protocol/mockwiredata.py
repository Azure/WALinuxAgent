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
import re

from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.common.utils.textutil import parse_doc, find, findall
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates
from tests.tools import load_bin_data, load_data, MagicMock, Mock
from azurelinuxagent.common.protocol.imds import IMDS_ENDPOINT
from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.utils.cryptutil import CryptUtil

DATA_FILE = {
        "version_info": "wire/version_info.xml",
        "goal_state": "wire/goal_state.xml",
        "hosting_env": "wire/hosting_env.xml",
        "shared_config": "wire/shared_config.xml",
        "certs": "wire/certs.xml",
        "ext_conf": "wire/ext_conf.xml",
        "manifest": "wire/manifest.xml",
        "ga_manifest": "wire/ga_manifest.xml",
        "trans_prv": "wire/trans_prv",
        "trans_cert": "wire/trans_cert",
        "test_ext": "ext/sample_ext-1.3.0.zip",
        "imds_info": "imds/valid.json",
        "remote_access": None,
        "in_vm_artifacts_profile": None,
        "vm_settings": None,
        "ETag": None
}

DATA_FILE_IN_VM_ARTIFACTS_PROFILE = DATA_FILE.copy()
DATA_FILE_IN_VM_ARTIFACTS_PROFILE["ext_conf"] = "wire/ext_conf_in_vm_artifacts_profile.xml"
DATA_FILE_IN_VM_ARTIFACTS_PROFILE["in_vm_artifacts_profile"] = "wire/in_vm_artifacts_profile.json"

DATA_FILE_IN_VM_META_DATA = DATA_FILE.copy()
DATA_FILE_IN_VM_META_DATA["ext_conf"] = "wire/ext_conf_in_vm_metadata.xml"

DATA_FILE_INVALID_VM_META_DATA = DATA_FILE.copy()
DATA_FILE_INVALID_VM_META_DATA["ext_conf"] = "wire/ext_conf_invalid_vm_metadata.xml"

DATA_FILE_NO_EXT = DATA_FILE.copy()
DATA_FILE_NO_EXT["ext_conf"] = "wire/ext_conf_no_extensions-block_blob.xml"

DATA_FILE_NOOP_GS = DATA_FILE.copy()
DATA_FILE_NOOP_GS["goal_state"] = "wire/goal_state_noop.xml"
DATA_FILE_NOOP_GS["ext_conf"] = None

DATA_FILE_EXT_NO_SETTINGS = DATA_FILE.copy()
DATA_FILE_EXT_NO_SETTINGS["ext_conf"] = "wire/ext_conf_no_settings.xml"

DATA_FILE_EXT_NO_PUBLIC = DATA_FILE.copy()
DATA_FILE_EXT_NO_PUBLIC["ext_conf"] = "wire/ext_conf_no_public.xml"

DATA_FILE_EXT_AUTOUPGRADE = DATA_FILE.copy()
DATA_FILE_EXT_AUTOUPGRADE["ext_conf"] = "wire/ext_conf_autoupgrade.xml"

DATA_FILE_EXT_INTERNALVERSION = DATA_FILE.copy()
DATA_FILE_EXT_INTERNALVERSION["ext_conf"] = "wire/ext_conf_internalversion.xml"

DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION = DATA_FILE.copy()
DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION["ext_conf"] = "wire/ext_conf_autoupgrade_internalversion.xml"

DATA_FILE_EXT_ROLLINGUPGRADE = DATA_FILE.copy()
DATA_FILE_EXT_ROLLINGUPGRADE["ext_conf"] = "wire/ext_conf_upgradeguid.xml"

DATA_FILE_EXT_SEQUENCING = DATA_FILE.copy()
DATA_FILE_EXT_SEQUENCING["ext_conf"] = "wire/ext_conf_sequencing.xml"

DATA_FILE_EXT_ADDITIONAL_LOCATIONS = DATA_FILE.copy()
DATA_FILE_EXT_ADDITIONAL_LOCATIONS["ext_conf"] = "wire/ext_conf_additional_locations.xml"

DATA_FILE_EXT_DELETION = DATA_FILE.copy()
DATA_FILE_EXT_DELETION["manifest"] = "wire/manifest_deletion.xml"

DATA_FILE_EXT_SINGLE = DATA_FILE.copy()
DATA_FILE_EXT_SINGLE["manifest"] = "wire/manifest_deletion.xml"

DATA_FILE_MULTIPLE_EXT = DATA_FILE.copy()
DATA_FILE_MULTIPLE_EXT["ext_conf"] = "wire/ext_conf_multiple_extensions.xml"

DATA_FILE_CASE_MISMATCH_EXT = DATA_FILE.copy()
DATA_FILE_CASE_MISMATCH_EXT["ext_conf"] = "wire/ext_conf_settings_case_mismatch.xml"

DATA_FILE_NO_CERT_FORMAT = DATA_FILE.copy()
DATA_FILE_NO_CERT_FORMAT["certs"] = "wire/certs_no_format_specified.xml"

DATA_FILE_CERT_FORMAT_NOT_PFX = DATA_FILE.copy()
DATA_FILE_CERT_FORMAT_NOT_PFX["certs"] = "wire/certs_format_not_pfx.xml"

DATA_FILE_REMOTE_ACCESS = DATA_FILE.copy()
DATA_FILE_REMOTE_ACCESS["goal_state"] = "wire/goal_state_remote_access.xml"
DATA_FILE_REMOTE_ACCESS["remote_access"] = "wire/remote_access_single_account.xml"

DATA_FILE_PLUGIN_SETTINGS_MISMATCH = DATA_FILE.copy()
DATA_FILE_PLUGIN_SETTINGS_MISMATCH["ext_conf"] = "wire/invalid_config/ext_conf_plugin_settings_version_mismatch.xml"

DATA_FILE_REQUIRED_FEATURES = DATA_FILE.copy()
DATA_FILE_REQUIRED_FEATURES["ext_conf"] = "wire/ext_conf_required_features.xml"

DATA_FILE_VM_SETTINGS = DATA_FILE.copy()
DATA_FILE_VM_SETTINGS["vm_settings"] = "hostgaplugin/vm_settings.json"
DATA_FILE_VM_SETTINGS["ETag"] = "1"
DATA_FILE_VM_SETTINGS["ext_conf"] = "hostgaplugin/ext_conf.xml"
DATA_FILE_VM_SETTINGS["in_vm_artifacts_profile"] = "hostgaplugin/in_vm_artifacts_profile.json"


class WireProtocolData(object):
    def __init__(self, data_files=None):
        if data_files is None:
            data_files = DATA_FILE
        self.emulate_stale_goal_state = False
        self.call_counts = {
            "comp=versions": 0,
            "/versions": 0,
            "/health": 0,
            "/HealthService": 0,
            "/vmAgentLog": 0,
            "goalstate": 0,
            "hostingEnvironmentConfig": 0,
            "sharedConfig": 0,
            "certificates": 0,
            "extensionsConfig": 0,
            "remoteaccessinfouri": 0,
            "extensionArtifact": 0,
            "agentArtifact": 0,
            "manifest.xml": 0,
            "manifest_of_ga.xml": 0,
            "ExampleHandlerLinux": 0,
            "in_vm_artifacts_profile": 0,
            "vm_settings": 0
        }
        self.status_blobs = []
        self.data_files = data_files
        self.version_info = None
        self.goal_state = None
        self.hosting_env = None
        self.shared_config = None
        self.certs = None
        self.ext_conf = None
        self.manifest = None
        self.ga_manifest = None
        self.trans_prv = None
        self.trans_cert = None
        self.ext = None
        self.remote_access = None
        self.in_vm_artifacts_profile = None
        self.vm_settings = None
        self.etag = None
        self.prev_etag = None
        self.imds_info = None

        self.reload()

    def reload(self):
        self.version_info = load_data(self.data_files.get("version_info"))
        self.goal_state = load_data(self.data_files.get("goal_state"))
        self.hosting_env = load_data(self.data_files.get("hosting_env"))
        self.shared_config = load_data(self.data_files.get("shared_config"))
        self.certs = load_data(self.data_files.get("certs"))
        self.ext_conf = self.data_files.get("ext_conf")
        if self.ext_conf is not None:
            self.ext_conf = load_data(self.ext_conf)
        self.manifest = load_data(self.data_files.get("manifest"))
        self.ga_manifest = load_data(self.data_files.get("ga_manifest"))
        self.trans_prv = load_data(self.data_files.get("trans_prv"))
        self.trans_cert = load_data(self.data_files.get("trans_cert"))
        self.imds_info = json.loads(load_data(self.data_files.get("imds_info")))
        self.ext = load_bin_data(self.data_files.get("test_ext"))

        vm_settings = self.data_files.get("vm_settings")
        if vm_settings is not None:
            self.vm_settings = load_data(self.data_files.get("vm_settings"))
            self.etag = self.data_files.get("ETag")

        remote_access_data_file = self.data_files.get("remote_access")
        if remote_access_data_file is not None:
            self.remote_access = load_data(remote_access_data_file)

        in_vm_artifacts_profile_file = self.data_files.get("in_vm_artifacts_profile")
        if in_vm_artifacts_profile_file is not None:
            self.in_vm_artifacts_profile = load_data(in_vm_artifacts_profile_file)

    def reset_call_counts(self):
        for counter in self.call_counts:
            self.call_counts[counter] = 0

    def mock_http_get(self, url, *_, **kwargs):
        content = ''
        response_headers = []

        resp = MagicMock()
        resp.status = httpclient.OK

        if "comp=versions" in url:  # wire server versions
            content = self.version_info
            self.call_counts["comp=versions"] += 1
        elif "/versions" in url:  # HostPlugin versions
            content = '["2015-09-01"]'
            self.call_counts["/versions"] += 1
        elif url.endswith("/health"):  # HostPlugin health
            content = ''
            self.call_counts["/health"] += 1
        elif "goalstate" in url:
            content = self.goal_state
            self.call_counts["goalstate"] += 1
        elif HttpRequestPredicates.is_hosting_environment_config_request(url):
            content = self.hosting_env
            self.call_counts["hostingEnvironmentConfig"] += 1
        elif HttpRequestPredicates.is_shared_config_request(url):
            content = self.shared_config
            self.call_counts["sharedConfig"] += 1
        elif HttpRequestPredicates.is_certificates_request(url):
            content = self.certs
            self.call_counts["certificates"] += 1
        elif HttpRequestPredicates.is_extensions_config_request(url):
            content = self.ext_conf
            self.call_counts["extensionsConfig"] += 1
        elif "remoteaccessinfouri" in url:
            content = self.remote_access
            self.call_counts["remoteaccessinfouri"] += 1
        elif ".vmSettings" in url or ".settings" in url:
            content = self.in_vm_artifacts_profile
            self.call_counts["in_vm_artifacts_profile"] += 1
        elif "/vmSettings" in url:
            if self.vm_settings is None:
                resp.status = httpclient.NOT_FOUND
            elif self.call_counts["vm_settings"] > 0 and self.prev_etag == self.etag:
                resp.status = httpclient.NOT_MODIFIED
            else:
                content = self.vm_settings
                response_headers = [('ETag', self.etag)]
                self.prev_etag = self.etag
            self.call_counts["vm_settings"] += 1
        elif '{0}/metadata/compute'.format(IMDS_ENDPOINT) in url:
            content = json.dumps(self.imds_info.get("compute", "{}"))

        else:
            # A stale GoalState results in a 400 from the HostPlugin
            # for which the HTTP handler in restutil raises ResourceGoneError
            if self.emulate_stale_goal_state:
                if "extensionArtifact" in url:
                    self.emulate_stale_goal_state = False
                    self.call_counts["extensionArtifact"] += 1
                    raise ResourceGoneError()
                else:
                    raise HttpError()

            # For HostPlugin requests, replace the URL with that passed
            # via the x-ms-artifact-location header
            if "extensionArtifact" in url:
                self.call_counts["extensionArtifact"] += 1
                if "headers" not in kwargs:
                    raise ValueError("HostPlugin request is missing the HTTP headers: {0}", kwargs)  # pylint: disable=raising-format-tuple
                if "x-ms-artifact-location" not in kwargs["headers"]:
                    raise ValueError("HostPlugin request is missing the x-ms-artifact-location header: {0}", kwargs)  # pylint: disable=raising-format-tuple
                url = kwargs["headers"]["x-ms-artifact-location"]

            if "manifest.xml" in url:
                content = self.manifest
                self.call_counts["manifest.xml"] += 1
            elif HttpRequestPredicates.is_ga_manifest_request(url):
                content = self.ga_manifest
                self.call_counts["manifest_of_ga.xml"] += 1
            elif "ExampleHandlerLinux" in url:
                content = self.ext
                self.call_counts["ExampleHandlerLinux"] += 1
                resp.read = Mock(return_value=content)
                return resp
            elif ".vmSettings" in url or ".settings" in url:
                content = self.in_vm_artifacts_profile
                self.call_counts["in_vm_artifacts_profile"] += 1
            else:
                raise NotImplementedError(url)

        resp.read = Mock(return_value=content.encode("utf-8"))
        resp.getheaders = Mock(return_value=response_headers)
        return resp

    def mock_http_post(self, url, *_, **__):
        content = None

        resp = MagicMock()
        resp.status = httpclient.OK

        if url.endswith('/HealthService'):
            self.call_counts['/HealthService'] += 1
            content = ''
        else:
            raise NotImplementedError(url)

        resp.read = Mock(return_value=content.encode("utf-8"))
        return resp

    def mock_http_put(self, url, data, **_):
        content = ''

        resp = MagicMock()
        resp.status = httpclient.OK

        if url.endswith('/vmAgentLog'):
            self.call_counts['/vmAgentLog'] += 1
        elif HttpRequestPredicates.is_storage_status_request(url):
            self.status_blobs.append(data)
        elif HttpRequestPredicates.is_host_plugin_status_request(url):
            self.status_blobs.append(WireProtocolData.get_status_blob_from_hostgaplugin_put_status_request(content))
        else:
            raise NotImplementedError(url)

        resp.read = Mock(return_value=content.encode("utf-8"))
        return resp

    def mock_crypt_util(self, *args, **kw):
        # Partially patch instance method of class CryptUtil
        cryptutil = CryptUtil(*args, **kw)
        cryptutil.gen_transport_cert = Mock(side_effect=self.mock_gen_trans_cert)
        return cryptutil
    
    def mock_gen_trans_cert(self, trans_prv_file, trans_cert_file):
        with open(trans_prv_file, 'w+') as prv_file:
            prv_file.write(self.trans_prv)

        with open(trans_cert_file, 'w+') as cert_file:
            cert_file.write(self.trans_cert)

    @staticmethod
    def get_status_blob_from_hostgaplugin_put_status_request(data):
        status_object = json.loads(data)
        content = status_object["content"]
        return base64.b64decode(content)

    def get_no_of_plugins_in_extension_config(self):
        if self.ext_conf is None:
            return 0
        ext_config_doc = parse_doc(self.ext_conf)
        plugins_list = find(ext_config_doc, "Plugins")
        return len(findall(plugins_list, "Plugin"))

    def get_no_of_extensions_in_config(self):
        if self.ext_conf is None:
            return 0
        ext_config_doc = parse_doc(self.ext_conf)
        plugin_settings = find(ext_config_doc, "PluginSettings")
        return len(findall(plugin_settings, "ExtensionRuntimeSettings")) + len(
            findall(plugin_settings, "RuntimeSettings"))

    #
    # Having trouble reading the regular expressions below? you are not alone!
    #
    # For the use of "(?<=" "(?=" see 7.2.1 in https://docs.python.org/3.1/library/re.html
    # For the use of "\g<1>" see backreferences in https://docs.python.org/3.1/library/re.html#re.sub
    #
    # Note that these regular expressions are not enough to parse all valid XML documents (e.g. they do
    # not account for metacharacters like < or > in the values) but they are good enough for the test
    # data. There are some basic checks, but the functions may not match valid XML or produce invalid
    # XML if their input is too complex.
    #
    @staticmethod
    def replace_xml_element_value(xml_document, element_name, element_value):
        element_regex = r'(?<=<{0}>).+(?=</{0}>)'.format(element_name)
        if not re.search(element_regex, xml_document):
            raise Exception("Can't find XML element '{0}' in {1}".format(element_name, xml_document))
        return re.sub(element_regex, element_value, xml_document)

    @staticmethod
    def replace_xml_attribute_value(xml_document, element_name, attribute_name, attribute_value):
        attribute_regex = r'(?<=<{0} )(.*{1}=")[^"]+(?="[^>]*>)'.format(element_name, attribute_name)
        if not re.search(attribute_regex, xml_document):
            raise Exception("Can't find attribute {0} in XML element '{1}'. Document: {2}".format(attribute_name, element_name, xml_document))
        return re.sub(attribute_regex, r'\g<1>{0}'.format(attribute_value), xml_document)

    def set_etag(self, etag, timestamp=None):
        """
        Sets the ETag for the mock response.
        This function is used to mock a new goal state, and it also updates the timestamp (extensionsLastModifiedTickCount) in vmSettings.
        """
        if timestamp is None:
            timestamp = datetime.datetime.utcnow()
        self.etag = etag
        try:
            vm_settings = json.loads(self.vm_settings)
            vm_settings["extensionsLastModifiedTickCount"] = timeutil.datetime_to_ticks(timestamp)
            self.vm_settings = json.dumps(vm_settings)
        except ValueError:  # some test data include syntax errors; ignore those
            pass

    def set_vm_settings_source(self, source):
        """
        Sets the "extensionGoalStatesSource" for the mock vm_settings data
        """
        vm_settings = json.loads(self.vm_settings)
        vm_settings["extensionGoalStatesSource"] = source
        self.vm_settings = json.dumps(vm_settings)

    def set_incarnation(self, incarnation, timestamp=None):
        """
        Sets the incarnation in the goal state, but not on its subcomponents (e.g. hosting env, shared config).
        This function is used to mock a new goal state, and it also updates the timestamp (createdOnTicks) in ExtensionsConfig.
        """
        self.goal_state = WireProtocolData.replace_xml_element_value(self.goal_state, "Incarnation", str(incarnation))
        if self.ext_conf is not None:
            if timestamp is None:
                timestamp = datetime.datetime.utcnow()
            self.ext_conf = WireProtocolData.replace_xml_attribute_value(self.ext_conf, "InVMGoalStateMetaData", "createdOnTicks", timeutil.datetime_to_ticks(timestamp))

    def set_container_id(self, container_id):
        self.goal_state = WireProtocolData.replace_xml_element_value(self.goal_state, "ContainerId", container_id)

    def set_role_config_name(self, role_config_name):
        self.goal_state = WireProtocolData.replace_xml_element_value(self.goal_state, "ConfigName", role_config_name)

    def set_hosting_env_deployment_name(self, deployment_name):
        self.hosting_env = WireProtocolData.replace_xml_attribute_value(self.hosting_env, "Deployment", "name", deployment_name)

    def set_shared_config_deployment_name(self, deployment_name):
        self.shared_config = WireProtocolData.replace_xml_attribute_value(self.shared_config, "Deployment", "name", deployment_name)

    def set_extensions_config_sequence_number(self, sequence_number):
        '''
        Sets the sequence number for *all* extensions
        '''
        self.ext_conf = WireProtocolData.replace_xml_attribute_value(self.ext_conf, "RuntimeSettings", "seqNo", str(sequence_number))

    def set_extensions_config_version(self, version):
        '''
        Sets the version for *all* extensions
        '''
        self.ext_conf = WireProtocolData.replace_xml_attribute_value(self.ext_conf, "Plugin", "version", version)

    def set_extensions_config_state(self, state):
        '''
        Sets the state for *all* extensions
        '''
        self.ext_conf = WireProtocolData.replace_xml_attribute_value(self.ext_conf, "Plugin", "state", state)

    def set_manifest_version(self, version):
        '''
        Sets the version of the extension manifest
        '''
        self.manifest = WireProtocolData.replace_xml_element_value(self.manifest, "Version", version)

    def set_extension_config(self, ext_conf_file):
        self.ext_conf = load_data(ext_conf_file)

    def set_ga_manifest(self, ga_manifest):
        self.ga_manifest = load_data(ga_manifest)

    def set_extension_config_requested_version(self, version):
        self.ext_conf = WireProtocolData.replace_xml_element_value(self.ext_conf, "Version", version)

    def set_ga_manifest_version_version(self, version):
        self.ga_manifest = WireProtocolData.replace_xml_element_value(self.ga_manifest, "Version", version)
