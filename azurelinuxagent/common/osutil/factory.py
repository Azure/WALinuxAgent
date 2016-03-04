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

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils.textutil import Version
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME

from .default import DefaultOSUtil
from .coreos import CoreOSUtil
from .debian import DebianOSUtil
from .freebsd import FreeBSDOSUtil
from .redhat import RedhatOSUtil, Redhat6xOSUtil
from .suse import SUSEOSUtil, SUSE11OSUtil
from .ubuntu import UbuntuOSUtil, Ubuntu12OSUtil, Ubuntu14OSUtil, \
                    UbuntuSnappyOSUtil

def get_osutil(distro_name=DISTRO_NAME, distro_version=DISTRO_VERSION,
               distro_full_name=DISTRO_FULL_NAME):
    if distro_name == "ubuntu":
        if Version(distro_version) == Version("12.04") or \
           Version(distro_version) == Version("12.10"):
            return Ubuntu12OSUtil()
        elif Version(distro_version) == Version("14.04") or \
             Version(distro_version) == Version("14.10"):
            return Ubuntu14OSUtil()
        elif distro_full_name == "Snappy Ubuntu Core":
            return UbuntuSnappyOSUtil()
        else:
            return UbuntuOSUtil()
    if distro_name == "coreos":
        return CoreOSUtil()
    if distro_name == "suse":
        if distro_full_name=='SUSE Linux Enterprise Server' and \
           Version(distro_version) < Version('12') or \
           distro_full_name == 'openSUSE' and \
           Version(distro_version) < Version('13.2'):
            return SUSE11OSUtil()
        else:
            return SUSEOSUtil()
    elif distro_name == "debian":
        return DebianOSUtil()
    elif distro_name == "redhat" or distro_name == "centos" or \
            distro_name == "oracle":
        if Version(distro_version) < Version("7"):
            return Redhat6xOSUtil()
        else:
            return RedhatOSUtil()
    elif distro_name == "freebsd":
        return FreeBSDOSUtil()
    else:
        logger.warn("Unable to load distro implemetation for {0}.", distro_name)
        logger.warn("Use default distro implemetation instead.")
        return DefaultOSUtil()

