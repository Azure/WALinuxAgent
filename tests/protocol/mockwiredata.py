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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

from tests.tools import *
from azurelinuxagent.future import httpclient
from azurelinuxagent.utils.cryptutil import CryptUtil

DATA_FILE = {
        "version_info": "wire/version_info.xml",
        "goal_state": "wire/goal_state.xml",
        "hosting_env": "wire/hosting_env.xml",
        "shared_config": "wire/shared_config.xml",
        "certs": "wire/certs.xml",
        "ext_conf": "wire/ext_conf.xml",
        "manifest": "wire/manifest.xml",
        "trans_prv": "wire/trans_prv",
        "trans_cert": "wire/trans_cert",
        "test_ext": "ext/sample_ext.zip"
}

DATA_FILE_NO_EXT = DATA_FILE.copy()
DATA_FILE_NO_EXT["goal_state"] = "wire/goal_state_no_ext.xml"

DATA_FILE_EXT_NO_SETTINGS = DATA_FILE.copy()
DATA_FILE_EXT_NO_SETTINGS["ext_conf"] = "wire/ext_conf_no_settings.xml"

DATA_FILE_EXT_NO_PUBLIC = DATA_FILE.copy()
DATA_FILE_EXT_NO_PUBLIC["ext_conf"] = "wire/ext_conf_no_public.xml"

class WireProtocolData(object):
    def __init__(self, data_files=DATA_FILE):
        self.version_info = load_data(data_files.get("version_info"))
        self.goal_state = load_data(data_files.get("goal_state"))
        self.hosting_env = load_data(data_files.get("hosting_env"))
        self.shared_config = load_data(data_files.get("shared_config"))
        self.certs = load_data(data_files.get("certs"))
        self.ext_conf = load_data(data_files.get("ext_conf"))
        self.manifest = load_data(data_files.get("manifest"))
        self.trans_prv = load_data(data_files.get("trans_prv"))
        self.trans_cert = load_data(data_files.get("trans_cert"))
        self.ext = load_bin_data(data_files.get("test_ext"))

    def mock_http_get(self, url, *args, **kwargs):
        content = None
        if "versions" in url:
            content = self.version_info
        elif "goalstate" in url:
            content = self.goal_state
        elif "hostingenvuri" in url:
            content = self.hosting_env
        elif "sharedconfiguri" in url:
            content = self.shared_config
        elif "certificatesuri" in url:
            content = self.certs
        elif "extensionsconfiguri" in url:
            content = self.ext_conf
        elif "manifest.xml" in url:
            content = self.manifest
        elif "ExampleHandlerLinux" in url:
            content = self.ext
            resp = MagicMock()
            resp.status = httpclient.OK
            resp.read = Mock(return_value=content)
            return resp
        else:
            raise Exception("Bad url {0}".format(url))
        resp = MagicMock()
        resp.status = httpclient.OK
        resp.read = Mock(return_value=content.encode("utf-8"))
        return resp

    def mock_crypt_util(self, *args, **kw):
        #Partially patch instance method of class CryptUtil
        cryptutil = CryptUtil(*args, **kw)
        cryptutil.gen_transport_cert = Mock(side_effect=self.mock_gen_trans_cert)
        return cryptutil
    
    def mock_gen_trans_cert(self, trans_prv_file, trans_cert_file):
        with open(trans_prv_file, 'w+') as prv_file:
            prv_file.write(self.trans_prv)

        with open(trans_cert_file, 'w+') as cert_file:
            cert_file.write(self.trans_cert)

