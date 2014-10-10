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
import os
import shutil
import tempfile
import subprocess
import walinuxagent.logger as logger

LibDir = '/var/lib/waagent'

def RestartNetwork():
    CurrentDistro.restartNetwork()

def OpenPortForDhcp():
    #Open DHCP port if iptables is enabled.
    # We supress error logging on error.
    Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)      
    Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",chk_err=False)

def CheckDependencies():
    CurrentDistro.checkDependencies()

__RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
                 "/etc/udev/rules.d/70-persistent-net.rules" ]
def RemoveRulesFiles(rulesFiles=__RulesFiles, libDir = LibDir):
    for src in rulesFiles:
        fileName = GetLastPathElement(src)
        dest = os.path.join(libDir, fileName)
        if os.path.isfile(dest):
            os.remove(dest)
        if os.path.isfile(src):
            logger.Warn("Move rules file {0} to {1}", fileName, dest)
            shutil.move(src, dest)

def RestoreRulesFiles(rulesFiles=__RulesFiles, libDir = LibDir):
    for dest in rulesFiles:
        fileName = GetLastPathElement(dest)
        src = os.path.join(libDir, fileName)
        if os.path.isfile(dest):
            continue
        if os.path.isfile(src):
            logger.Warn("Move rules file {0} to {1}", fileName, dest)
            shutil.move(src, dest)

def RegisterAgentService():
    CurrentDistro.registerAgentService()

def UnregisterAgentService():
    CurrentDistro.unregisterAgentService()

def SetSshClientAliveInterval():
    CurrentDistro.setSshClientAliveInterval()

"""
Define distro specific behavior. DefaultDistro class defines default behavior 
for all distros. Each concrete distro classes could overwrite default behavior
if needed.

Distro classes should be transparent to caller. 
"""
class DefaultDistro():
    def checkDependencies():
        pass

    def restartNetwork():
        pass

    def registerAgentService():
        pass

    def unregisterAgentService():
        pass

    def setSshClientAliveInterval():
        filepath = "/etc/ssh/sshd_config"
        options = filter(lambda opt: not opt.startswith("ClientAliveInterval"), 
                        GetFileContents(filepath).split('\n'))
        options.append("ClientAliveInterval 180")
        ReplaceFileContentsAtomic(filepath, '\n'.join(options))
        logger.Info("Configured SSH client probing to keep connections alive.")

class DebianDistro():
    pass

class UbuntuDistro():
    pass

class RedHatDistro():
    pass

class FedoraDistro():
    pass

class CoreOSDistro():
    pass

class GentooDistro():
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
    elif name == 'centos' or name == 'redhat':
        return RedhatDistro()
    elif name == 'fedora':
        return FedoraDistro()
    elif name == 'debian':
        return DebianDistro()
    elif name == 'coreos':
        return CoreOSDistro()
    elif name == 'gentoo':
        return CoreOSDistro()
    elif name == 'suse':
        return SUSEDistro()
    else:
        return DefaultDistro()

CurrentDistroInfo = GetdistroInfo()
CurrentDistro = GetDistro(CurrentDistroInfo)
