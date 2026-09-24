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

import os

from azurelinuxagent.ga.state_dir import get_state_dir, initialize_state_dir
from tests.lib.tools import AgentTestCase, patch


class TestStateDir(AgentTestCase):
    def test_get_state_dir_should_return_state_subdirectory_of_lib_dir(self):
        with patch("azurelinuxagent.common.conf.get_lib_dir", return_value="/var/lib/waagent"):
            self.assertEqual(get_state_dir(), os.path.join("/var/lib/waagent", "state"))

    def test_initialize_state_dir_should_create_directory(self):
        state_dir_path = os.path.join(self.tmp_dir, "state")
        with patch("azurelinuxagent.ga.state_dir.get_state_dir", return_value=state_dir_path):
            initialize_state_dir()
            self.assertTrue(os.path.isdir(state_dir_path))

    def test_initialize_state_dir_should_log_warning_on_failure(self):
        with patch("azurelinuxagent.ga.state_dir.get_state_dir", side_effect=Exception("test error")):
            with patch("azurelinuxagent.ga.state_dir.logger.warn") as mock_warn:
                initialize_state_dir()
                self.assertIn("test error", mock_warn.call_args[0][0])
