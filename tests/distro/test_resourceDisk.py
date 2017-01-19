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

import sys
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.daemon.resourcedisk import get_resourcedisk_handler
from tests.tools import *


class TestResourceDisk(AgentTestCase):
    def test_mkfile(self):
        # setup
        test_file = os.path.join(self.tmp_dir, 'test_file')
        file_size = 1024 * 128
        if os.path.exists(test_file):
            os.remove(test_file)

        # execute
        get_resourcedisk_handler().mkfile(test_file, file_size)

        # assert
        assert os.path.exists(test_file)

        # cleanup
        os.remove(test_file)

    def test_mkfile_dd_fallback(self):
        with patch.object(shellutil, "run") as run_patch:
            # setup
            run_patch.return_value = 1
            test_file = os.path.join(self.tmp_dir, 'test_file')
            file_size = 1024 * 128

            # execute
            if sys.version_info >= (3,3):
                with patch("os.posix_fallocate",
                           side_effect=Exception('failure')):
                    get_resourcedisk_handler().mkfile(test_file, file_size)
            else:
                get_resourcedisk_handler().mkfile(test_file, file_size)

            # assert
            assert run_patch.call_count > 1
            assert "fallocate" in run_patch.call_args_list[0][0][0]
            assert "dd if" in run_patch.call_args_list[-1][0][0]

    def test_mkfile_xfs_fs(self):
        # setup
        test_file = os.path.join(self.tmp_dir, 'test_file')
        file_size = 1024 * 128
        if os.path.exists(test_file):
            os.remove(test_file)

        # execute
        resource_disk_handler = get_resourcedisk_handler()
        resource_disk_handler.fs = 'xfs'

        with patch.object(shellutil, "run") as run_patch:
            resource_disk_handler.mkfile(test_file, file_size)

            # assert
            if sys.version_info >= (3,3):
                with patch("os.posix_fallocate") as posix_fallocate:
                    assert posix_fallocate.assert_not_called()

            assert run_patch.call_count == 1
            assert "dd if" in run_patch.call_args_list[0][0][0]


    def test_change_partition_type(self):
        resource_handler = get_resourcedisk_handler()
        # test when sfdisk --part-type does not exist
        with patch.object(shellutil, "run_get_output",
                          side_effect=[[1, ''], [0, '']]) as run_patch:
            resource_handler.change_partition_type(suppress_message=True, option_str='')

            # assert
            assert run_patch.call_count == 2
            assert "sfdisk --part-type" in run_patch.call_args_list[0][0][0]
            assert "sfdisk -c" in run_patch.call_args_list[1][0][0]

        # test when sfdisk --part-type exists
        with patch.object(shellutil, "run_get_output",
                          side_effect=[[0, '']]) as run_patch:
            resource_handler.change_partition_type(suppress_message=True, option_str='')

            # assert
            assert run_patch.call_count == 1
            assert "sfdisk --part-type" in run_patch.call_args_list[0][0][0]


if __name__ == '__main__':
    unittest.main()
