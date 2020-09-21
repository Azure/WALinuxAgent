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

import unittest

from tests.tools import AgentTestCase, patch, DEFAULT
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler


class TestResourceDisk(AgentTestCase):
    def test_mount_flags_empty(self):
        partition = '/dev/sdb1'
        mountpoint = '/mnt/resource'
        options = None
        expected = 'mount -t ext3 /dev/sdb1 /mnt/resource'
        rdh = ResourceDiskHandler()
        mount_string = rdh.get_mount_string(options, partition, mountpoint)
        self.assertEqual(expected, mount_string)

    def test_mount_flags_many(self):
        partition = '/dev/sdb1'
        mountpoint = '/mnt/resource'
        options = 'noexec,noguid,nodev'
        expected = 'mount -t ext3 -o noexec,noguid,nodev /dev/sdb1 /mnt/resource'
        rdh = ResourceDiskHandler()
        mount_string = rdh.get_mount_string(options, partition, mountpoint)
        self.assertEqual(expected, mount_string)

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    @patch('azurelinuxagent.daemon.resourcedisk.default.ResourceDiskHandler.mkfile')
    @patch('azurelinuxagent.daemon.resourcedisk.default.os.path.isfile', return_value=False)
    @patch(
        'azurelinuxagent.daemon.resourcedisk.default.ResourceDiskHandler.check_existing_swap_file',
        return_value=False)
    def test_create_swap_space( # pylint: disable=too-many-arguments
            self,
            mock_check_existing_swap_file, # pylint: disable=unused-argument
            mock_isfile, # pylint: disable=unused-argument
            mock_mkfile, # pylint: disable=unused-argument
            mock_run,
            mock_run_get_output):
        mount_point = '/mnt/resource'
        size_mb = 128

        rdh = ResourceDiskHandler()

        def rgo_side_effect(*args, **kwargs): # pylint: disable=unused-argument
            if args[0] == 'swapon -s':
                return (0, 'Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/mnt/resource/swapfile                 \tfile    \t131068\t0\t-2\n')
            return DEFAULT

        def run_side_effect(*args, **kwargs): # pylint: disable=unused-argument
            # We have to change the default mock behavior to return a falsey value
            # (instead of the default truthy of the mock), because we are testing
            # really for the exit code of the the swapon command to return 0.
            if 'swapon' in args[0]:
                return 0
            return None

        mock_run_get_output.side_effect = rgo_side_effect
        mock_run.side_effect = run_side_effect

        rdh.create_swap_space(
            mount_point=mount_point,
            size_mb=size_mb
        )


if __name__ == '__main__':
    unittest.main()
