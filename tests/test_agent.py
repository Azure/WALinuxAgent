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

import mock
import os.path

from azurelinuxagent.agent import *
from azurelinuxagent.common.conf import *

from tests.tools import *


class TestAgent(AgentTestCase):

    def test_accepts_configuration_path(self):
        conf_path = os.path.join(data_dir, "test_waagent.conf")
        c, f, v, cfp = parse_args(["-configuration-path:" + conf_path])
        self.assertEqual(cfp, conf_path)

    @patch("os.path.exists", return_value=True)
    def test_checks_configuration_path(self, mock_exists):
        conf_path = "/foo/bar-baz/something.conf"
        c, f, v, cfp = parse_args(["-configuration-path:"+conf_path])
        self.assertEqual(cfp, conf_path)
        self.assertEqual(mock_exists.call_count, 1)

    @patch("sys.stderr")
    @patch("os.path.exists", return_value=False)
    @patch("sys.exit", side_effect=Exception)
    def test_rejects_missing_configuration_path(self, mock_exit, mock_exists, mock_stderr):
        try:
            c, f, v, cfp = parse_args(["-configuration-path:/foo/bar.conf"])
            self.assertTrue(False)
        except Exception:
            self.assertEqual(mock_exit.call_count, 1)

    def test_configuration_path_defaults_to_none(self):
        c, f, v, cfp = parse_args([])
        self.assertEqual(cfp, None)

    def test_agent_accepts_configuration_path(self):
        Agent(False,
                conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
        self.assertTrue(conf.get_fips_enabled())

    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_uses_default_configuration_path(self, mock_load):
        Agent(False)
        mock_load.assert_called_once_with("/etc/waagent.conf")

    @patch("azurelinuxagent.daemon.get_daemon_handler")
    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_does_not_pass_configuration_path(self,
                mock_load, mock_handler):

        mock_daemon = Mock()
        mock_daemon.run = Mock()
        mock_handler.return_value = mock_daemon

        agent = Agent(False)
        agent.daemon()

        mock_daemon.run.assert_called_once_with(child_args=None)
        mock_load.assert_called_once()

    @patch("azurelinuxagent.daemon.get_daemon_handler")
    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_passes_configuration_path(self, mock_load, mock_handler):

        mock_daemon = Mock()
        mock_daemon.run = Mock()
        mock_handler.return_value = mock_daemon

        agent = Agent(False, conf_file_path="/foo/bar.conf")
        agent.daemon()

        mock_daemon.run.assert_called_once_with(child_args="-configuration-path:/foo/bar.conf")
        mock_load.assert_called_once()
