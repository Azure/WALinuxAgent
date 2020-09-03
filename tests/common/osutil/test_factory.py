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

from azurelinuxagent.common.osutil.factory import _get_osutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.osutil.arch import ArchUtil
from azurelinuxagent.common.osutil.clearlinux import ClearLinuxUtil
from azurelinuxagent.common.osutil.coreos import CoreOSUtil
from azurelinuxagent.common.osutil.debian import DebianOSBaseUtil, DebianOSModernUtil
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
from tests.tools import AgentTestCase, patch


class TestOsUtilFactory(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    @patch("azurelinuxagent.common.logger.warn")
    def test_get_osutil_it_should_return_default(self, patch_logger):
        ret = _get_osutil(distro_name="",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == DefaultOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(patch_logger.call_count, 1)
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_ubuntu(self):
        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="",
                          distro_version="10.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == UbuntuOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="",
                          distro_version="12.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == Ubuntu12OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="trusty",
                          distro_version="14.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == Ubuntu14OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="xenial",
                          distro_version="16.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == Ubuntu16OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="bionic",
                          distro_version="18.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == Ubuntu18OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="focal",
                          distro_version="20.04",
                          distro_full_name="")
        self.assertTrue(type(ret) == Ubuntu18OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

        ret = _get_osutil(distro_name="ubuntu",
                          distro_code_name="",
                          distro_version="10.04",
                          distro_full_name="Snappy Ubuntu Core")
        self.assertTrue(type(ret) == UbuntuSnappyOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

    def test_get_osutil_it_should_return_arch(self):
        ret = _get_osutil(distro_name="arch",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == ArchUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_clear_linux(self):
        ret = _get_osutil(distro_name="clear linux",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="Clear Linux")
        self.assertTrue(type(ret) == ClearLinuxUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_alpine(self):
        ret = _get_osutil(distro_name="alpine",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == AlpineOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_kali(self):
        ret = _get_osutil(distro_name="kali",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == DebianOSBaseUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_coreos(self):
        ret = _get_osutil(distro_name="coreos",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == CoreOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_suse(self):
        ret = _get_osutil(distro_name="suse",
                          distro_code_name="",
                          distro_version="10",
                          distro_full_name="")
        self.assertTrue(type(ret) == SUSEOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="suse",
                          distro_code_name="",
                          distro_full_name="SUSE Linux Enterprise Server",
                          distro_version="11")
        self.assertTrue(type(ret) == SUSE11OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="suse",
                          distro_code_name="",
                          distro_full_name="openSUSE",
                          distro_version="12")
        self.assertTrue(type(ret) == SUSE11OSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_debian(self):
        ret = _get_osutil(distro_name="debian",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="7")
        self.assertTrue(type(ret) == DebianOSBaseUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="debian",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="8")
        self.assertTrue(type(ret) == DebianOSModernUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "walinuxagent")

    def test_get_osutil_it_should_return_redhat(self):
        ret = _get_osutil(distro_name="redhat",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="centos",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="oracle",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="6")
        self.assertTrue(type(ret) == Redhat6xOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="redhat",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="centos",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

        ret = _get_osutil(distro_name="oracle",
                          distro_code_name="",
                          distro_full_name="",
                          distro_version="7")
        self.assertTrue(type(ret) == RedhatOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_euleros(self):
        ret = _get_osutil(distro_name="euleros",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == RedhatOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_freebsd(self):
        ret = _get_osutil(distro_name="freebsd",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == FreeBSDOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_openbsd(self):
        ret = _get_osutil(distro_name="openbsd",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == OpenBSDOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_bigip(self):
        ret = _get_osutil(distro_name="bigip",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == BigIpOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_gaia(self):
        ret = _get_osutil(distro_name="gaia",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == GaiaOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_iosxe(self):
        ret = _get_osutil(distro_name="iosxe",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == IosxeOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")

    def test_get_osutil_it_should_return_openwrt(self):
        ret = _get_osutil(distro_name="openwrt",
                          distro_code_name="",
                          distro_version="",
                          distro_full_name="")
        self.assertTrue(type(ret) == OpenWRTOSUtil) # pylint: disable=unidiomatic-typecheck
        self.assertEqual(ret.get_service_name(), "waagent")
