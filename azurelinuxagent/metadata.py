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

import re
import platform

def GetDistroInfo():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', str(platform.release()))
        osInfo = ['freebsd', release, '', 'freebsd']
    if 'linux_distribution' in dir(platform):
        osInfo = list(platform.linux_distribution(full_distribution_name=0))
        fullName = platform.linux_distribution()[0].strip()
        osInfo.append(fullName)
    else:
        osInfo = platform.dist()

    #Remove trailing whitespace and quote in distro name
    osInfo[0] = osInfo[0].strip('"').strip(' ').lower() 
    return osInfo

GuestAgentName = "AzureLinuxAgent"
GuestAgentLongName = "Azure Linux Agent"
GuestAgentVersion='2.1.0-pre'
GuestAgentLongVersion = "{0}-{1}".format(GuestAgentName, GuestAgentVersion)
GuestAgentDescription = """\
The Azure Linux Agent supports the provisioning and running of Linux
VMs in the Azure cloud. This package should be installed on Linux disk
images that are built to run in the Azure environment.
"""

__DistroInfo = GetDistroInfo()
DistroName = __DistroInfo[0]
DistroVersion = __DistroInfo[1]
DistroCodeName = __DistroInfo[2]
DistroFullName = __DistroInfo[3]

