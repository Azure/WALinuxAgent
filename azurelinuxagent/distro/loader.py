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

import azurelinuxagent.logger as logger
from azurelinuxagent.utils.textutil import Version
from azurelinuxagent.metadata import DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME
from azurelinuxagent.distro.default.distro import DefaultDistro
from azurelinuxagent.distro.ubuntu.distro import UbuntuDistro, \
                                                 Ubuntu14Distro, \
                                                 Ubuntu12Distro, \
                                                 UbuntuSnappyDistro
from azurelinuxagent.distro.redhat.distro import RedhatDistro, Redhat6xDistro
from azurelinuxagent.distro.coreos.distro import CoreOSDistro
from azurelinuxagent.distro.suse.distro import SUSE11Distro, SUSEDistro
from azurelinuxagent.distro.debian.distro import DebianDistro

def get_distro(distro_name=DISTRO_NAME, distro_version=DISTRO_VERSION,
               distro_full_name=DISTRO_FULL_NAME):
    if distro_name == "ubuntu":
        if Version(distro_version) == Version("12.04") or \
           Version(distro_version) == Version("12.10"):
            return Ubuntu12Distro()
        elif Version(distro_version) == Version("14.04") or \
             Version(distro_version) == Version("14.10"):
            return Ubuntu14Distro()
        elif distro_full_name == "Snappy Ubuntu Core":
            return UbuntuSnappyDistro()
        else:
            return UbuntuDistro()
    if distro_name == "coreos":
        return CoreOSDistro()
    if distro_name == "suse":
        if distro_full_name=='SUSE Linux Enterprise Server' and \
           Version(distro_version) < Version('12') or \
           distro_full_name == 'openSUSE' and \
           Version(distro_version) < Version('13.2'):
            return SUSE11Distro()
        else:
            return SUSEDistro()
    elif distro_name == "debian":
        return DebianDistro()
    elif distro_name == "redhat" or distro_name == "centos" or \
            distro_name == "oracle":
        if Version(distro_version) < Version("7"):
            return Redhat6xDistro()
        else:
            return RedhatDistro()
    else:
        logger.warn("Unable to load distro implemetation for {0}.", distro_name)
        logger.warn("Use default distro implemetation instead.")
        return DefaultDistro()

