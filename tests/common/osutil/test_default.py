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

import azurelinuxagent.common.osutil.default as osutil
import azurelinuxagent.common.utils.shellutil as shellutil
import mock
from tests.tools import *


class TestOSUtil(AgentTestCase):
    def test_restart(self):
        # setup
        retries = 3
        ifname = 'dummy'
        patch = mock.patch.object(shellutil, 'run')
        patch.return_value = 1
        patch_run = patch.start()

        # execute
        osutil.DefaultOSUtil.restart_if(osutil.DefaultOSUtil(), ifname=ifname,retries=retries, wait=0)

        # assert
        self.assertEqual(patch_run.call_count, retries)
        self.assertEqual(patch_run.call_args_list[0][0][0], 'ifdown {0} && ifup {0}'.format(ifname))

if __name__ == '__main__':
    unittest.main()

