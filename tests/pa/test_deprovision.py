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

from tests.tools import *
from azurelinuxagent.pa.deprovision import get_deprovision_handler


class TestDeprovision(AgentTestCase):
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
