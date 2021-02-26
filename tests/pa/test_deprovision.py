# Copyright 2016 Microsoft Corporation
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
import tempfile
import unittest

import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.pa.deprovision import get_deprovision_handler
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler
from tests.tools import AgentTestCase, distros, Mock, patch


class TestDeprovision(AgentTestCase):
    @patch('signal.signal')
    @patch('azurelinuxagent.common.osutil.get_osutil')
    @patch('azurelinuxagent.common.protocol.util.get_protocol_util')
    @patch('azurelinuxagent.pa.deprovision.default.read_input')
    def test_confirmation(self,
            mock_read, mock_protocol, mock_util, mock_signal):  # pylint: disable=unused-argument
        dh = DeprovisionHandler()

        dh.setup = Mock()
        dh.setup.return_value = ([], [])
        dh.do_actions = Mock()

        # Do actions if confirmed
        mock_read.return_value = "y"
        dh.run()
        self.assertEqual(1, dh.do_actions.call_count)

        # Skip actions if not confirmed
        mock_read.return_value = "n"
        dh.run()
        self.assertEqual(1, dh.do_actions.call_count)

        # Do actions if forced
        mock_read.return_value = "n"
        dh.run(force=True)
        self.assertEqual(2, dh.do_actions.call_count)

    @distros("ubuntu")
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    def test_del_lib_dir_files(self,
                        distro_name,
                        distro_version,
                        distro_full_name,
                        mock_conf):
        dirs = [
            'WALinuxAgent-2.2.26/config',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/config',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/status'
        ]
        files = [
            'HostingEnvironmentConfig.xml',
            'Incarnation',
            'Protocol',
            'SharedConfig.xml',
            'WireServerEndpoint',
            'Extensions.1.xml',
            'ExtensionsConfig.1.xml',
            'GoalState.1.xml',
            'Extensions.2.xml',
            'ExtensionsConfig.2.xml',
            'GoalState.2.xml',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/config/42.settings',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/config/HandlerStatus',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/config/HandlerState',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/status/12.notstatus',
            'Microsoft.Azure.Extensions.CustomScript-2.0.6/mrseq',
            'WALinuxAgent-2.2.26/config/0.settings'
        ]

        tmp = tempfile.mkdtemp()
        mock_conf.return_value = tmp
        for d in dirs:
            fileutil.mkdir(os.path.join(tmp, d))
        for f in files:
            fileutil.write_file(os.path.join(tmp, f), "Value")

        deprovision_handler = get_deprovision_handler(distro_name,
                                                      distro_version,
                                                      distro_full_name)
        warnings = []
        actions = []
        deprovision_handler.del_lib_dir_files(warnings, actions)
        deprovision_handler.del_ext_handler_files(warnings, actions)

        self.assertTrue(len(warnings) == 0)
        self.assertTrue(len(actions) == 2)
        self.assertEqual(fileutil.rm_files, actions[0].func)
        self.assertEqual(fileutil.rm_files, actions[1].func)
        self.assertEqual(11, len(actions[0].args))
        self.assertEqual(3, len(actions[1].args))
        for f in actions[0].args:
            self.assertTrue(os.path.basename(f) in files)
        for f in actions[1].args:
            self.assertTrue(f[len(tmp)+1:] in files)

    @distros("redhat")
    def test_deprovision(self,
                         distro_name,
                         distro_version,
                         distro_full_name):
        deprovision_handler = get_deprovision_handler(distro_name,
                                                      distro_version,
                                                      distro_full_name)
        warnings, actions = deprovision_handler.setup(deluser=False)  # pylint: disable=unused-variable
        assert any("/etc/resolv.conf" in w for w in warnings)

    @distros("ubuntu")
    def test_deprovision_ubuntu(self,
                                distro_name,
                                distro_version,
                                distro_full_name):
        deprovision_handler = get_deprovision_handler(distro_name,
                                                      distro_version,
                                                      distro_full_name)

        with patch("os.path.realpath", return_value="/run/resolvconf/resolv.conf"):
            warnings, actions = deprovision_handler.setup(deluser=False)  # pylint: disable=unused-variable
            assert any("/etc/resolvconf/resolv.conf.d/tail" in w for w in warnings)


if __name__ == '__main__':
    unittest.main()
