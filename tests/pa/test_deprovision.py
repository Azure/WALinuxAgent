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
# Requires Python 2.4+ and Openssl 1.0+
#

import signal
import tempfile

import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.pa.deprovision import get_deprovision_handler
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler
from tests.tools import *


class TestDeprovision(AgentTestCase):
    @patch('signal.signal')
    @patch('azurelinuxagent.common.osutil.get_osutil')
    @patch('azurelinuxagent.common.protocol.get_protocol_util')
    @patch('azurelinuxagent.pa.deprovision.default.read_input')
    def test_confirmation(self,
            mock_read, mock_protocol, mock_util, mock_signal):
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

    @patch("azurelinuxagent.pa.deprovision.default.DeprovisionHandler.cloud_init_dirs")
    @patch("azurelinuxagent.pa.deprovision.default.DeprovisionHandler.cloud_init_files")
    def test_del_cloud_init_without_once(self,
                mock_files,
                mock_dirs):
        deprovision_handler = get_deprovision_handler("","","")
        deprovision_handler.del_cloud_init([], [],
                            include_once=False, deluser=False)

        mock_dirs.assert_called_with(include_once=False)
        mock_files.assert_called_with(include_once=False, deluser=False)

    @patch("signal.signal")
    @patch("azurelinuxagent.common.protocol.get_protocol_util")
    @patch("azurelinuxagent.common.osutil.get_osutil")
    @patch("azurelinuxagent.pa.deprovision.default.DeprovisionHandler.cloud_init_dirs")
    @patch("azurelinuxagent.pa.deprovision.default.DeprovisionHandler.cloud_init_files")
    def test_del_cloud_init(self,
                mock_files,
                mock_dirs,
                mock_osutil,
                mock_util,
                mock_signal):
        try:
            with tempfile.NamedTemporaryFile() as f:
                warnings = []
                actions = []

                dirs = [tempfile.mkdtemp()]
                mock_dirs.return_value = dirs

                files = [f.name]
                mock_files.return_value = files

                deprovision_handler = get_deprovision_handler("","","")
                deprovision_handler.del_cloud_init(warnings, actions,
                        deluser=True)

                mock_dirs.assert_called_with(include_once=True)
                mock_files.assert_called_with(include_once=True, deluser=True)

                self.assertEqual(len(warnings), 0)
                self.assertEqual(len(actions), 2)
                for da in actions:
                    if da.func == fileutil.rm_dirs:
                        self.assertEqual(da.args, dirs)
                    elif da.func == fileutil.rm_files:
                        self.assertEqual(da.args, files)
                    else:
                        self.assertTrue(False)

                try:
                    for da in actions:
                        da.invoke()
                    self.assertEqual(len([d for d in dirs if os.path.isdir(d)]), 0)
                    self.assertEqual(len([f for f in files if os.path.isfile(f)]), 0)
                except Exception as e:
                    self.assertTrue(False, "Exception {0}".format(e))
        except OSError:
            # Ignore the error caused by removing the file within the "with"
            pass
    
    @distros("ubuntu")
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    def test_del_lib_dir_files(self,
                        distro_name,
                        distro_version,
                        distro_full_name,
                        mock_conf):
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
            'GoalState.2.xml'
        ]

        tmp = tempfile.mkdtemp()
        mock_conf.return_value = tmp
        for f in files:
            fileutil.write_file(os.path.join(tmp, f), "Value")

        deprovision_handler = get_deprovision_handler(distro_name,
                                                      distro_version,
                                                      distro_full_name)
        warnings = []
        actions = []
        deprovision_handler.del_lib_dir_files(warnings, actions)

        self.assertTrue(len(warnings) == 0)
        self.assertTrue(len(actions) == 1)
        self.assertEqual(fileutil.rm_files, actions[0].func)
        self.assertTrue(len(actions[0].args) > 0)
        for f in actions[0].args:
            self.assertTrue(os.path.basename(f) in files)


    @distros("redhat")
    def test_deprovision(self,
                         distro_name,
                         distro_version,
                         distro_full_name):
        deprovision_handler = get_deprovision_handler(distro_name,
                                                      distro_version,
                                                      distro_full_name)
        warnings, actions = deprovision_handler.setup(deluser=False)
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
            warnings, actions = deprovision_handler.setup(deluser=False)
            assert any("/etc/resolvconf/resolv.conf.d/tail" in w for w in warnings)

if __name__ == '__main__':
    unittest.main()
