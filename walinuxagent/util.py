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

import platform

LibDir = '/var/lib/waagent'

def SetFileContent(path, content):
    pass

def GetFileContet(path):
    pass

def RestartNetwork():
    CurrentDistro.restartNetwork()

def OpenPortForDhcp():
    #Open DHCP port if iptables is enabled.
    Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)  # We supress error logging on error.
    Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)  # We supress error logging on error.

"""
Define distro specific behavior. DefaultDistro class defines default behavior for all distros. Each concrete
distro classes could overwrite default behavior if needed.

All distro classes should be transparent to caller. 
"""
class DefaultDistro():
    def restartNetwork():
        pass

class DebianDistro():
    pass

class RedHatDistro():
    pass

class CoreOSDistro():
    pass

class SUSEDistro():
    pass

def GetdistroInfo():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', str(platform.release()))
        distroInfo = ['freebsd', release, '']
    if 'linux_distribution' in dir(platform):
        distroInfo = list(platform.linux_distribution(full_distribution_name = 0))
    else:
        distroInfo = platform.dist()

    distroInfo[0] = distroInfo[0].strip('"').strip(' ').lower() # remove trailing whitespace and quote in distro name
    return distroInfo

def GetDistro(distroInfo):
    name = distroInfo[0]
    version = distroInfo[1]
    codeName = distroInfo[2]

    if name == 'ubuntu':
        return UbuntuDistro()
    elif name == 'centos' or name == 'redhat' or name == 'fedoro':
        return RedhatDistro()
    elif name == 'debian':
        return DebianDistro()
    elif name == 'coreos':
        return CoreOSDistro()
    elif name == 'suse':
        return SUSEDistro()
    else:
        return DefaultDistro()

CurrentDistroInfo = GetdistroInfo()
CurrentDistro = GetDistro(CurrentDistroInfo)

