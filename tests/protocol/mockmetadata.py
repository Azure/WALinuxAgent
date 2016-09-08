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

from tests.tools import *
from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.utils.cryptutil import CryptUtil

DATA_FILE = {
        "identity": "metadata/identity.json",
        "certificates": "metadata/certificates.json",
        "certificates_data": "metadata/certificates_data.json",
        "ext_handlers": "metadata/ext_handlers.json",
        "ext_handler_pkgs": "metadata/ext_handler_pkgs.json",
        "trans_prv": "metadata/trans_prv",
        "trans_cert": "metadata/trans_cert",        
}

DATA_FILE_NO_EXT = DATA_FILE.copy()
DATA_FILE_NO_EXT["ext_handlers"] = "metadata/ext_handlers_no_ext.json"

class MetadataProtocolData(object):
    def __init__(self, data_files):
        self.identity = load_data(data_files.get("identity"))
        self.certificates = load_data(data_files.get("certificates"))
        self.certificates_data = load_data(data_files.get("certificates_data"))
        self.ext_handlers = load_data(data_files.get("ext_handlers"))
        self.ext_handler_pkgs = load_data(data_files.get("ext_handler_pkgs"))
        self.trans_prv = load_data(data_files.get("trans_prv"))
        self.trans_cert = load_data(data_files.get("trans_cert"))
        
    def mock_http_get(self, url, *args, **kwargs):
        content = None
        if url.count(u"identity?") > 0:
            content = self.identity
        elif url.count(u"certificates") > 0:
            content = self.certificates
        elif url.count(u"certificates_data") > 0:
            content = self.certificates_data
        elif url.count(u"extensionHandlers") > 0:
            content = self.ext_handlers
        elif url.count(u"versionUri") > 0:
            content = self.ext_handler_pkgs
        else:
            raise Exception("Bad url {0}".format(url))
        resp = MagicMock()
        resp.status = httpclient.OK
        if content is None:
            resp.read = Mock(return_value=None)
        else:
            resp.read = Mock(return_value=content.encode("utf-8"))
        return resp

