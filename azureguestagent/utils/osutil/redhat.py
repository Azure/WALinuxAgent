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
import re
import pwd
import shutil
import tempfile
import subprocess
import socket
import array
import struct
import fcntl
import time
import base64
import azureguestagent.logger as logger
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.textutil as textutil
from azureguestagent.utils.osutil.default import DefaultOSUtil

class RedhatOSUtil(DefaultOSUtil):
    def __init__(self):
        super(RedhatOSUtil, self).__init__()
        self.sshdConfigPath = '/etc/ssh/sshd_config'
        self.opensslCmd = '/usr/bin/openssl'
        self.configPath = '/etc/waagent.conf'
        self.selinux=None

    def StartNetwork(self):
        return shellutil.Run("/sbin/service networking start", chk_err=False)

    def RestartSshService(self):
        return shellutil.Run("/sbin/service sshd condrestart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("/sbin/service waagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("/sbin/service waagent start", chk_err=False)

    #Override
    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

class Redhat7OSUtil(RedhatOSUtil):
    def __init__(self):
        super(Redhat7OSUtil, self).__init__()

    def SetHostname(self, hostname):
        super(Redhat7OSUtil, self).SetHostname(hostname)
        fileutil.UpdateConfigFile('/etc/sysconfig/network', 
                                  'HOSTNAME',
                                  'HOSTNAME={0}'.format(hostname))
    
    def SetDhcpHostname(self, hostname):
        ifname = self.GetInterfaceName()
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        fileutil.UpdateConfigFile(filepath,
                                  'DHCP_HOSTNAME',
                                  'DHCP_HOSTNAME={0}'.format(hostname))


