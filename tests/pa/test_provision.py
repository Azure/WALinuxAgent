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

import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.protocol import OVF_FILE_NAME
from azurelinuxagent.pa.provision import get_provision_handler
from tests.tools import *


class TestProvision(AgentTestCase):
 
    @distros("redhat")
    def test_provision(self, distro_name, distro_version, distro_full_name):
        provision_handler = get_provision_handler(distro_name, distro_version, 
                                                  distro_full_name)
        mock_osutil = MagicMock()
        mock_osutil.decode_customdata = Mock(return_value="")
        
        provision_handler.osutil = mock_osutil
        provision_handler.protocol_util.osutil = mock_osutil
        provision_handler.protocol_util.get_protocol_by_file = MagicMock()
        provision_handler.protocol_util.get_protocol = MagicMock()
       
        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        ovfenv_file = os.path.join(self.tmp_dir, OVF_FILE_NAME)
        ovfenv_data = load_data("ovf-env.xml")
        fileutil.write_file(ovfenv_file, ovfenv_data)
         
        provision_handler.run()

    def test_customdata(self):
        base64data = 'Q3VzdG9tRGF0YQ=='
        data = DefaultOSUtil().decode_customdata(base64data)
        fileutil.write_file(tempfile.mktemp(), data)


if __name__ == '__main__':
    unittest.main()

