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

from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME 
from .default import ResourceDiskHandler
from .freebsd import FreeBSDResourceDiskHandler
from .openbsd import OpenBSDResourceDiskHandler
from .openwrt import OpenWRTResourceDiskHandler


def get_resourcedisk_handler(distro_name=DISTRO_NAME, 
                             distro_version=DISTRO_VERSION, # pylint: disable=W0613
                             distro_full_name=DISTRO_FULL_NAME): # pylint: disable=W0613
    if distro_name == "freebsd":
        return FreeBSDResourceDiskHandler()

    if distro_name == "openbsd":
        return OpenBSDResourceDiskHandler()

    if distro_name == "openwrt":
        return OpenWRTResourceDiskHandler()

    return ResourceDiskHandler()

