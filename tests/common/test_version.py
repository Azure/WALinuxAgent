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

from __future__ import print_function

import os
import textwrap

import mock

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY
from azurelinuxagent.common.version import set_current_agent, \
    AGENT_LONG_VERSION, AGENT_VERSION, AGENT_NAME, AGENT_NAME_PATTERN, \
    get_f5_platform, get_distro, get_lis_version, PY_VERSION_MAJOR, \
    PY_VERSION_MINOR
from tests.tools import AgentTestCase, open_patch, patch


def freebsd_system():
    return ["FreeBSD"]


def freebsd_system_release(x, y, z): # pylint: disable=unused-argument,invalid-name
    return "10.0"


def openbsd_system():
    return ["OpenBSD"]


def openbsd_system_release(x, y, z): # pylint: disable=unused-argument,invalid-name
    return "20.0"


def default_system():
    return [""]


def default_system_no_linux_distro():
    return '', '', ''


def default_system_exception():
    raise Exception


def is_platform_dist_supported():
    # platform.dist() and platform.linux_distribution() is deprecated from Python 3.8+
    if PY_VERSION_MAJOR == 3 and PY_VERSION_MINOR >= 8:
        return False
    return True


class TestAgentVersion(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    @mock.patch('platform.system', side_effect=freebsd_system)
    @mock.patch('re.sub', side_effect=freebsd_system_release)
    def test_distro_is_correct_format_when_freebsd(self, platform_system_name, mock_variable): # pylint: disable=unused-argument
        osinfo = get_distro()
        freebsd_list = ['freebsd', "10.0", '', 'freebsd']
        self.assertListEqual(freebsd_list, osinfo)

    @mock.patch('platform.system', side_effect=openbsd_system)
    @mock.patch('re.sub', side_effect=openbsd_system_release)
    def test_distro_is_correct_format_when_openbsd(self, platform_system_name, mock_variable): # pylint: disable=unused-argument
        osinfo = get_distro()
        openbsd_list = ['openbsd', "20.0", '', 'openbsd']
        self.assertListEqual(openbsd_list, osinfo)

    @mock.patch('platform.system', side_effect=default_system)
    def test_distro_is_correct_format_when_default_case(self, *args): # pylint: disable=unused-argument
        default_list = ['', '', '', '']
        unknown_list = ['unknown', 'FFFF', '', '']

        if is_platform_dist_supported():
            with patch('platform.dist', side_effect=default_system_no_linux_distro):
                osinfo = get_distro()
                self.assertListEqual(default_list, osinfo)
        else:
            # platform.dist() is deprecated in Python 3.7+ and would throw, resulting in unknown distro
            osinfo = get_distro()
            self.assertListEqual(unknown_list, osinfo)

    @mock.patch('platform.system', side_effect=default_system)
    def test_distro_is_correct_for_exception_case(self, *args): # pylint: disable=unused-argument
        default_list = ['unknown', 'FFFF', '', '']

        if is_platform_dist_supported():
            with patch('platform.dist', side_effect=default_system_exception):
                osinfo = get_distro()
        else:
            # platform.dist() is deprecated in Python 3.7+ so we can't patch it, but it would throw
            # as well, resulting in the same unknown distro
            osinfo = get_distro()

        self.assertListEqual(default_list, osinfo)

    def test_get_lis_version_should_return_a_string(self):
        """
        On a Hyper-V guest with the LIS drivers installed as a module,
        this function should return a string of the version, like
        '4.3.5'. Anywhere else it should return 'Absent' and possibly
        return 'Failed' if an exception was raised, so we check that
        it returns a string'.
        """
        lis_version = get_lis_version()
        self.assertIsInstance(lis_version, str)


class TestCurrentAgentName(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    @patch("os.getcwd", return_value="/default/install/directory")
    def test_extract_name_finds_installed(self, mock_cwd): # pylint: disable=unused-argument
        current_agent, current_version = set_current_agent()
        self.assertEqual(AGENT_LONG_VERSION, current_agent)
        self.assertEqual(AGENT_VERSION, str(current_version))

    @patch("os.getcwd", return_value="/")
    def test_extract_name_root_finds_installed(self, mock_cwd): # pylint: disable=unused-argument
        current_agent, current_version = set_current_agent()
        self.assertEqual(AGENT_LONG_VERSION, current_agent)
        self.assertEqual(AGENT_VERSION, str(current_version))

    @patch("os.getcwd")
    def test_extract_name_in_path_finds_installed(self, mock_cwd):
        path = os.path.join(conf.get_lib_dir(), EVENTS_DIRECTORY)
        mock_cwd.return_value = path
        current_agent, current_version = set_current_agent()
        self.assertEqual(AGENT_LONG_VERSION, current_agent)
        self.assertEqual(AGENT_VERSION, str(current_version))

    @patch("os.getcwd")
    def test_extract_name_finds_latest_agent(self, mock_cwd):
        path = os.path.join(conf.get_lib_dir(), "{0}-{1}".format(
            AGENT_NAME,
            "1.2.3"))
        mock_cwd.return_value = path
        agent = os.path.basename(path)
        version = AGENT_NAME_PATTERN.match(agent).group(1)
        current_agent, current_version = set_current_agent()
        self.assertEqual(agent, current_agent)
        self.assertEqual(version, str(current_version))


class TestGetF5Platforms(AgentTestCase):
    def test_get_f5_platform_bigip_12_1_1(self):
        version_file = textwrap.dedent("""
        Product: BIG-IP
        Version: 12.1.1
        Build: 0.0.184
        Sequence: 12.1.1.0.0.184.0
        BaseBuild: 0.0.184
        Edition: Final
        Date: Thu Aug 11 17:09:01 PDT 2016
        Built: 160811170901
        Changelist: 1874858
        JobID: 705993""")

        mocked_open = mock.mock_open(read_data=version_file)
        with patch(open_patch(), mocked_open):
            platform = get_f5_platform()
            self.assertTrue(platform[0] == 'bigip')
            self.assertTrue(platform[1] == '12.1.1')
            self.assertTrue(platform[2] == 'bigip')
            self.assertTrue(platform[3] == 'BIG-IP')

    def test_get_f5_platform_bigip_12_1_0_hf1(self):
        version_file = textwrap.dedent("""
        Product: BIG-IP
        Version: 12.1.0
        Build: 1.0.1447
        Sequence: 12.1.0.1.0.1447.0
        BaseBuild: 0.0.1434
        Edition: Hotfix HF1
        Date: Wed Jun  8 13:41:59 PDT 2016
        Built: 160608134159
        Changelist: 1773831
        JobID: 673467""")

        mocked_open = mock.mock_open(read_data=version_file)
        with patch(open_patch(), mocked_open):
            platform = get_f5_platform()
            self.assertTrue(platform[0] == 'bigip')
            self.assertTrue(platform[1] == '12.1.0')
            self.assertTrue(platform[2] == 'bigip')
            self.assertTrue(platform[3] == 'BIG-IP')

    def test_get_f5_platform_bigip_12_0_0(self):
        version_file = textwrap.dedent("""
        Product: BIG-IP
        Version: 12.0.0
        Build: 0.0.606
        Sequence: 12.0.0.0.0.606.0
        BaseBuild: 0.0.606
        Edition: Final
        Date: Fri Aug 21 13:29:22 PDT 2015
        Built: 150821132922
        Changelist: 1486072
        JobID: 536212""")

        mocked_open = mock.mock_open(read_data=version_file)
        with patch(open_patch(), mocked_open):
            platform = get_f5_platform()
            self.assertTrue(platform[0] == 'bigip')
            self.assertTrue(platform[1] == '12.0.0')
            self.assertTrue(platform[2] == 'bigip')
            self.assertTrue(platform[3] == 'BIG-IP')

    def test_get_f5_platform_iworkflow_2_0_1(self):
        version_file = textwrap.dedent("""
        Product: iWorkflow
        Version: 2.0.1
        Build: 0.0.9842
        Sequence: 2.0.1.0.0.9842.0
        BaseBuild: 0.0.9842
        Edition: Final
        Date: Sat Oct  1 22:52:08 PDT 2016
        Built: 161001225208
        Changelist: 1924048
        JobID: 734712""")

        mocked_open = mock.mock_open(read_data=version_file)
        with patch(open_patch(), mocked_open):
            platform = get_f5_platform()
            self.assertTrue(platform[0] == 'iworkflow')
            self.assertTrue(platform[1] == '2.0.1')
            self.assertTrue(platform[2] == 'iworkflow')
            self.assertTrue(platform[3] == 'iWorkflow')

    def test_get_f5_platform_bigiq_5_1_0(self):
        version_file = textwrap.dedent("""
        Product: BIG-IQ
        Version: 5.1.0
        Build: 0.0.631
        Sequence: 5.1.0.0.0.631.0
        BaseBuild: 0.0.631
        Edition: Final
        Date: Thu Sep 15 19:55:43 PDT 2016
        Built: 160915195543
        Changelist: 1907534
        JobID: 726344""")

        mocked_open = mock.mock_open(read_data=version_file)
        with patch(open_patch(), mocked_open):
            platform = get_f5_platform()
            self.assertTrue(platform[0] == 'bigiq')
            self.assertTrue(platform[1] == '5.1.0')
            self.assertTrue(platform[2] == 'bigiq')
            self.assertTrue(platform[3] == 'BIG-IQ')
