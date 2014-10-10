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

"""
File operation util functions
"""
def GetFileContents(filepath,asbin=False):
    """
    Read and return contents of 'filepath'.
    """
    mode='r'
    if asbin:
        mode+='b'
    c=None
    try:
        with open(filepath, mode) as F :
            c=F.read()
    except IOError, e:
        logger.Error('Reading from file {0} Exception is {1}', filepath, e)
        return None        
    return c

def SetFileContents(filepath, contents):
    """
    Write 'contents' to 'filepath'.
    """
    if type(contents) == str :
        contents=contents.encode('latin-1', 'ignore')
    try:
        with open(filepath, "wb+") as F :
            F.write(contents)
    except IOError, e:
        logger.Error('Writing to file {0} Exception is {1}', filepath, e)
        return None
    return 0

def AppendFileContents(filepath, contents):
    """
    Append 'contents' to 'filepath'.
    """
    if type(contents) == str :
        contents=contents.encode('latin-1')
    try: 
        with open(filepath, "a+") as F :
            F.write(contents)
    except IOError, e:
        logger.Error('Appending to file {0} Exception is {1}', filepath, e)
        return 1
    return 0

def ReplaceFileContentsAtomic(filepath, contents):
    """
    Write 'contents' to 'filepath' by creating a temp file, and replacing original.
    """
    handle, temp = tempfile.mkstemp(dir = os.path.dirname(filepath))
    if type(contents) == str :
        contents=contents.encode('latin-1')
    try:
        os.write(handle, contents)
    except IOError, e:
        logger.Error('Write to file {0}, Exception is {1}', filepath, e)
        return 1
    finally:
        os.close(handle)

    try:
        os.rename(temp, filepath)
    except IOError, e:
        logger.Info('Rename {0} to {1}, Exception is {2}',temp,  filepath, e)
        logger.Info('Remove original file and retry')
        try:
            os.remove(filepath)
        except IOError, e:
            logger.Error('Remove {0}, Exception is {1}',temp,  filepath, e)

        try:
            os.rename(temp, filepath)
        except IOError, e:
            logger.Error('Rename {0} to {1}, Exception is {2}',temp,  filepath, e)
            return 1
    return 0

def GetLastPathElement(path):
    head, tail = os.path.split(path)
    return tail

#End File operation util functions

"""
Shell command util functions
"""
def Run(cmd, chk_err=True):
    """
    Calls RunGetOutput on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode,out=RunGetOutput(cmd,chk_err)
    return retcode

def RunGetOutput(cmd, chk_err=True):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    logger.Verbose("Run cmd '{0}'", cmd)
    try:                                     
        output=subprocess.check_output(cmd,stderr=subprocess.STDOUT,shell=True)
    except subprocess.CalledProcessError,e :
        if chk_err :
            logger.Error("Run cmd '{0}' failed", e.cmd)
            logger.Error("Error Code:{0}", e.returncode)
            logger.Error("Result:{0}", e.output[:-1].decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    return 0, output.decode('latin-1')

def RunSendStdin(cmd, input, chk_err=True):
    """
    Wrapper for subprocess.Popen.
    Execute 'cmd', sending 'input' to STDIN of 'cmd'.
    Returns return code and STDOUT, trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    logger.Verbose("Run cmd '{0}'", cmd)
    try:                                     
        me=subprocess.Popen([cmd], shell=True, stdin=subprocess.PIPE,
                            stderr=subprocess.STDOUT,stdout=subprocess.PIPE)
        output=me.communicate(input)
    except OSError , e :
        if chk_err :
            logger.Error("Run cmd '{0}' failed", e.cmd)
            logger.Error("Error Code:{0}", e.returncode)
            logger.Error("Result:{0}", e.output[:-1].decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    if me.returncode is not 0 and chk_err is True:
        logger.Error("Run cmd '{0}' failed", cmd)
        logger.Error("Error Code:{0}", me.returncode)
        logger.Error("Result:{0}", output[0].decode('latin-1'))
    return me.returncode, output[0].decode('latin-1')

#End shell command util functions

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
