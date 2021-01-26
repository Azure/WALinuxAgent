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

from distutils.version import LooseVersion as Version  # pylint: disable=no-name-in-module, import-error

from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME
from .arch import ArchDeprovisionHandler
from .clearlinux import ClearLinuxDeprovisionHandler
from .coreos import CoreOSDeprovisionHandler
from .default import DeprovisionHandler
from .ubuntu import UbuntuDeprovisionHandler, Ubuntu1804DeprovisionHandler


def get_deprovision_handler(distro_name=DISTRO_NAME, 
                            distro_version=DISTRO_VERSION,
                            distro_full_name=DISTRO_FULL_NAME):
    if distro_name == "arch":
        return ArchDeprovisionHandler()
    if distro_name == "ubuntu":
        if Version(distro_version) >= Version('18.04'):
            return Ubuntu1804DeprovisionHandler()
        else:
            return UbuntuDeprovisionHandler()
    if distro_name == "coreos":
        return CoreOSDeprovisionHandler()
    if "Clear Linux" in distro_full_name:
        return ClearLinuxDeprovisionHandler()  # pylint: disable=E1120

    return DeprovisionHandler()

