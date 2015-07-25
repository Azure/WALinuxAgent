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

import tests.env
from tests.tools import *
import unittest
from azurelinuxagent.distro.redhat.osutil import RedhatOSUtil

test_pubkey="""\
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA2wo22vf1N8NWE+5lLfit
T7uzkfwqdw0IAoHZ0l2BtP0ajy6f835HCR3w3zLWw5ut7Xvyo26x1OMOzjo5lqtM
h8iyQwfHtWf6Cekxfkf+6Pca99bNuDgwRopOTOyoVgwDzJB0+slpn/sJjeGbhxJl
ToT8tNPLrBmnnpaMZLMIANcPQtTRCQcV/ycv+/omKXFB+zULYkN8v22o5mysoCuQ
fzXiJP3Mlnf+V2XMl1WAJylhOJif04K8j+G8oF5ECBIQiph4ZLQS1yTYlozPXU8k
8vB6A5+UiOGxBnOQYnp42cS5d4qSQ8LORCRGXrCj4DCP+lvkUDLUHx2WN+1ivZkO
fQIBIw==
-----END PUBLIC KEY-----
"""

expected_ssh_rsa_pubkey="""\
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA2wo22vf1N8NWE+5lLfitT7uzkfwqdw0IAoHZ0l2BtP0ajy6f835HCR3w3zLWw5ut7Xvyo26x1OMOzjo5lqtMh8iyQwfHtWf6Cekxfkf+6Pca99bNuDgwRopOTOyoVgwDzJB0+slpn/sJjeGbhxJlToT8tNPLrBmnnpaMZLMIANcPQtTRCQcV/ycv+/omKXFB+zULYkN8v22o5mysoCuQfzXiJP3Mlnf+V2XMl1WAJylhOJif04K8j+G8oF5ECBIQiph4ZLQS1yTYlozPXU8k8vB6A5+UiOGxBnOQYnp42cS5d4qSQ8LORCRGXrCj4DCP+lvkUDLUHx2WN+1ivZkOfQ==
"""

class TestRedhat(unittest.TestCase):
    def test_RsaPublicKeyToSshRsa(self):
        OSUtil = RedhatOSUtil()
        ssh_rsa_pubkey = OSUtil.asn1_to_ssh_rsa(test_pubkey)
        self.assertEquals(expected_ssh_rsa_pubkey, ssh_rsa_pubkey)

if __name__ == '__main__':
    unittest.main()
