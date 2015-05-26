# Windows Azure Linux Agent
#
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
import azureguestagent.osinfo as osinfo
from default import DefaultOSUtil, OSUtilError
from debian import DebianOSUtil
from ubuntu import UbuntuOSUtil, Ubuntu1204OSUtil
from redhat import RedhatOSUtil, RedhatOSUtil
from coreos import CoreOSOSUtil
from suse import SUSEOSUtil, SUSE12OSUtil
from gentoo import GentooOSUtil
from fedora import FedoraOSUtil
from freebsd import FreeBSDOSUtil

def GetOSUtil(osInfo):
    name = osInfo[0]
    version = osInfo[1]
    codeName = osInfo[2]
    fullName = osInfo[3]

    if name == 'ubuntu':
        if version == '12.04':
            return Ubuntu1204OSUtil()
        else:
            return UbuntuOSUtil()
    elif name == 'centos' or name == 'redhat':
        if version < '7.0':
            return RedhatOSUtil()
        else:
            return Redhat7OSUtil()
    elif name == 'fedora':
        return FedoraOSUtil()
    elif name == 'debian':
        return DebianOSUtil()
    elif name == 'coreos':
        return CoreOSOSUtil()
    elif name == 'gentoo':
        return CoreOSOSUtil()
    elif name == 'suse':
        if fullName == 'SUSE Linux Enterprise Server' and version < '12' \
                or fullName == 'openSUSE' and version < '13.2':
            return SUSEOSUtil()
        else:
            return SUSE12OSUtil()
    elif name == 'freebsd':
        return FreeBSDOSUtil()
    return default.DefaultOSUtil()

CurrOSUtil = GetOSUtil(osinfo.CurrOSInfo)

