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

import mock
from tests.tools import *

import azurelinuxagent.daemon.scvmm as scvmm
from azurelinuxagent.daemon.main import *
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class TestSCVMM(AgentTestCase):
    def test_scvmm_detection_with_file(self):
        # setup
        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        conf.get_detect_scvmm_env = Mock(return_value=True)
        scvmm_file = os.path.join(self.tmp_dir, scvmm.VMM_CONF_FILE_NAME)
        fileutil.write_file(scvmm_file, "")

        with patch.object(scvmm.ScvmmHandler, 'start_scvmm_agent') as po:
            with patch('os.listdir', return_value=["sr0", "sr1", "sr2"]):
                with patch('time.sleep', return_value=0):
                    # execute
                    failed = False
                    try:
                        scvmm.get_scvmm_handler().run()
                    except:
                        failed = True
                    # assert
                    self.assertTrue(failed)
                    self.assertTrue(po.call_count == 1)
                    # cleanup
                    os.remove(scvmm_file)


    def test_scvmm_detection_with_multiple_cdroms(self):
        # setup
        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        conf.get_detect_scvmm_env = Mock(return_value=True)

        # execute
        with mock.patch.object(DefaultOSUtil, 'mount_dvd') as patch_mount:
            with patch('os.listdir', return_value=["sr0", "sr1", "sr2"]):
                scvmm.ScvmmHandler().detect_scvmm_env()
                # assert
                assert patch_mount.call_count == 3
                assert patch_mount.call_args_list[0][1]['dvd_device'] == '/dev/sr0'
                assert patch_mount.call_args_list[1][1]['dvd_device'] == '/dev/sr1'
                assert patch_mount.call_args_list[2][1]['dvd_device'] == '/dev/sr2'


    def test_scvmm_detection_without_file(self):
        # setup
        conf.get_dvd_mount_point = Mock(return_value=self.tmp_dir)
        conf.get_detect_scvmm_env = Mock(return_value=True)
        scvmm_file = os.path.join(self.tmp_dir, scvmm.VMM_CONF_FILE_NAME)
        if os.path.exists(scvmm_file):
            os.remove(scvmm_file)

        with mock.patch.object(scvmm.ScvmmHandler, 'start_scvmm_agent') as patch_start:
            # execute
            scvmm.ScvmmHandler().detect_scvmm_env()
            # assert
            patch_start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
