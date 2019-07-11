# Copyright 2019 Microsoft Corporation
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

from azurelinuxagent.common.osutil.factory import get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.osutil.arch import ArchUtil
from azurelinuxagent.common.osutil.clearlinux import ClearLinuxUtil
from azurelinuxagent.common.osutil.coreos import CoreOSUtil
from azurelinuxagent.common.osutil.debian import DebianOSUtil, DebianOS8Util
from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil
from azurelinuxagent.common.osutil.openbsd import OpenBSDOSUtil
from azurelinuxagent.common.osutil.redhat import RedhatOSUtil, Redhat6xOSUtil
from azurelinuxagent.common.osutil.suse import SUSEOSUtil, SUSE11OSUtil
from azurelinuxagent.common.osutil.ubuntu import UbuntuOSUtil, Ubuntu12OSUtil, Ubuntu14OSUtil, \
    UbuntuSnappyOSUtil, Ubuntu16OSUtil, Ubuntu18OSUtil
from azurelinuxagent.common.osutil.alpine import AlpineOSUtil
from azurelinuxagent.common.osutil.bigip import BigIpOSUtil
from azurelinuxagent.common.osutil.gaia import GaiaOSUtil
from azurelinuxagent.common.osutil.iosxe import IosxeOSUtil
from azurelinuxagent.common.osutil.openwrt import OpenWRTOSUtil
from tests.tools import *


class DefaultOsUtilTestCase(AgentTestCase):

    def test_get_osutil_in_travis_environment_it_should_return_trusty(self):
        mock_os_environ = {
            'TRAVIS': 'true',
            '_system_name': 'Ubuntu',
            '_system_version': '14.04',
            'TRAVIS_DIST': 'trusty',
        }
        with patch.dict("os.environ", mock_os_environ):
            ret = get_osutil()
            self.assertTrue(type(ret) == Ubuntu14OSUtil)

    def test_get_osutil_in_travis_environment_it_should_return_xenial(self):
        mock_os_environ = {
            'TRAVIS': 'true',
            '_system_name': 'Ubuntu',
            '_system_version': '16.04',
            'TRAVIS_DIST': 'xenial',
        }
        with patch.dict("os.environ", mock_os_environ):
            ret = get_osutil()
            self.assertTrue(type(ret) == Ubuntu16OSUtil)

    def test_get_osutil_in_travis_environment_it_should_raise_and_catch(self):
        # Leave out necessary environment variables to fail the retrieval and fall back to the given parameters
        mock_os_environ = {
            'TRAVIS': 'true'
        }
        with patch.dict("os.environ", mock_os_environ, clear=True):
            ret = get_osutil(distro_name="debian",
                             distro_version="8")
            self.assertTrue(type(ret) == DebianOS8Util)

    @patch("azurelinuxagent.common.logger.warn")
    def test_get_osutil_it_should_return_default(self, patch_logger):
        ret = get_osutil(distro_name="",
                         distro_code_name="",
                         distro_version="",
                         distro_full_name="")
        self.assertTrue(type(ret) == DefaultOSUtil)
        self.assertEquals(patch_logger.call_count, 1)

    def test_get_osutil_it_should_return_ubuntu(self):
        ret = get_osutil(distro_name="ubuntu",
                         distro_version="10.04")
        self.assertTrue(type(ret) == UbuntuOSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

        ret = get_osutil(distro_name="ubuntu",
                         distro_version="12.04")
        self.assertTrue(type(ret) == Ubuntu12OSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

        ret = get_osutil(distro_name="ubuntu",
                         distro_version="14.04")
        self.assertTrue(type(ret) == Ubuntu14OSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

        ret = get_osutil(distro_name="ubuntu",
                         distro_version="16.04")
        self.assertTrue(type(ret) == Ubuntu16OSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

        ret = get_osutil(distro_name="ubuntu",
                         distro_version="18.04")
        self.assertTrue(type(ret) == Ubuntu18OSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

        ret = get_osutil(distro_name="ubuntu",
                         distro_version="10.04",
                         distro_full_name="Snappy Ubuntu Core")
        self.assertTrue(type(ret) == UbuntuSnappyOSUtil)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

    def test_get_osutil_it_should_return_arch(self):
        ret = get_osutil(distro_name="arch")
        self.assertTrue(type(ret) == ArchUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_clear_linux(self):
        ret = get_osutil(distro_name="clear linux",
                         distro_full_name="Clear Linux")
        self.assertTrue(type(ret) == ClearLinuxUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_alpine(self):
        ret = get_osutil(distro_name="alpine")
        self.assertTrue(type(ret) == AlpineOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_kali(self):
        ret = get_osutil(distro_name="kali")
        self.assertTrue(type(ret) == DebianOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_coreos(self):
        ret = get_osutil(distro_name="coreos")
        self.assertTrue(type(ret) == CoreOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_suse(self):
        ret = get_osutil(distro_name="suse",
                         distro_version="10")
        self.assertTrue(type(ret) == SUSEOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="suse",
                         distro_full_name="SUSE Linux Enterprise Server",
                         distro_version="11")
        self.assertTrue(type(ret) == SUSE11OSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="suse",
                         distro_full_name="openSUSE",
                         distro_version="12")
        self.assertTrue(type(ret) == SUSE11OSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_debian(self):
        ret = get_osutil(distro_name="debian",
                         distro_version="7")
        self.assertTrue(type(ret) == DebianOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="debian",
                         distro_version="8")
        self.assertTrue(type(ret) == DebianOS8Util)
        self.assertEquals(ret.get_service_name(), "walinuxagent")

    def test_get_osutil_it_should_return_redhat(self):
        ret = get_osutil(distro_name="redhat",
                         distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="centos",
                         distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="oracle",
                         distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="redhat",
                         distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="centos",
                         distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

        ret = get_osutil(distro_name="oracle",
                         distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_euleros(self):
        ret = get_osutil(distro_name="euleros")
        self.assertTrue(type(ret) == RedhatOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_freebsd(self):
        ret = get_osutil(distro_name="freebsd")
        self.assertTrue(type(ret) == FreeBSDOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_openbsd(self):
        ret = get_osutil(distro_name="openbsd")
        self.assertTrue(type(ret) == OpenBSDOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_bigip(self):
        ret = get_osutil(distro_name="bigip")
        self.assertTrue(type(ret) == BigIpOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_gaia(self):
        ret = get_osutil(distro_name="gaia")
        self.assertTrue(type(ret) == GaiaOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_iosxe(self):
        ret = get_osutil(distro_name="iosxe")
        self.assertTrue(type(ret) == IosxeOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_openwrt(self):
        ret = get_osutil(distro_name="openwrt")
        self.assertTrue(type(ret) == OpenWRTOSUtil)
        self.assertEquals(ret.get_service_name(), "waagent")
