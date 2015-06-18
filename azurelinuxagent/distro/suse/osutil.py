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

import os
import re
import pwd
import shutil
import socket
import array
import struct
import fcntl
import time
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.textutil as textutil
from azurelinuxagent.metadata import DistroName, DistroVersion, DistroFullName
from azurelinuxagent.distro.default.osutil import DefaultOSUtil

class SUSE11OSUtil(DefaultOSUtil):
    def __init__(self):
        super(SUSE11OSUtil, self).__init__()
        self.dhcpClientName='dhcpcd'

    def SetHostname(self, hostname):
        fileutil.SetFileContents('/etc/HOSTNAME', hostname)
        shellutil.Run("hostname {0}".format(hostname), chk_err=False)

    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof {0}".format(self.dhcpClientName))
        return ret[1] if ret[0] == 0 else None
    
    def IsDhcpEnabled(self):
        return True

    def StopDhcpService(self):
        cmd = "/sbin/service {0} stop".format(self.dhcpClientName)
        return shellutil.Run(cmd, chk_err=False)

    def StartDhcpService(self):
        cmd = "/sbin/service {0} start".format(self.dhcpClientName)
        return shellutil.Run(cmd, chk_err=False)

    def StartNetwork(self) :
        return shellutil.Run("/sbin/service start network", chk_err=False)

    def RestartSshService(self):
        return shellutil.Run("/sbin/service sshd restart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("/sbin/service waagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("/sbin/service waagent start", chk_err=False)
    
    def RegisterAgentService(self):
        ret = shellutil.Run("insserv waagent", chk_err=False)
        if ret != 0:
            return ret
        ret = super(SUSE11OSUtil, self).RegisterAgentService()
        return ret
    
    def UnregisterAgentService(self):
        ret = super(SUSE11OSUtil, self).UnregisterAgentService()
        if ret != 0:
            return ret
        return shellutil.Run("insserv -r waagent", chk_err=False)

class SUSEOSUtil(SUSE11OSUtil):
    def __init__(self):
        super(SUSEOSUtil, self).__init__()
        self.dhcpClientName = 'wickedd-dhcp4'

